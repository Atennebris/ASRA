"""main.py's __main__ startup probe distinguishes four port-8000-occupied causes before ever
calling uvicorn.run() -- see that block's own comment for the full reasoning. This covers the
plain top-level helpers it relies on to do that (both callable directly, no need to go through
__main__ or a real subprocess launch).

_existing_asra_status's "stale" case is the regression guard for a real, confirmed incident: an
already-running ASRA process kept getting silently reused across a later main.py edit (a new
route/filter) even though its own hot-reloaded templates immediately started calling that new
code -- an opaque, traceback-free "Internal Server Error" on the very next render, since Python
code (unlike templates, see main.py's own comment on _SOURCE_MTIME_AT_STARTUP) never hot-reloads
without a real process restart.
"""
import http.server
import socket
import subprocess
import sys
import threading
import time

import main


def test_port_has_live_listener_is_true_for_a_real_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        assert main._port_has_live_listener("127.0.0.1", port) is True
    finally:
        server.close()


def test_port_has_live_listener_is_false_when_nothing_is_listening():
    # Bind-then-immediately-close to get a real, currently-unused ephemeral port rather than a
    # hardcoded number that could collide with something else on the test machine.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    assert main._port_has_live_listener("127.0.0.1", port) is False


def test_existing_asra_status_is_foreign_when_nothing_is_listening():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    assert main._existing_asra_status("127.0.0.1", port) == "foreign"


class _FakeHealthServer:
    """A real, minimal HTTP server standing in for a running ASRA instance's own
    /api/system-health -- _existing_asra_status makes a real socket connection, so a monkeypatched
    http.client would miss the actual wire behavior this is meant to guard."""

    def __init__(self, source_mtime_header=None, status=200):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                if outer.source_mtime_header is not None:
                    self.send_header("X-ASRA-Source-Mtime", outer.source_mtime_header)
                self.end_headers()
                self.wfile.write(b"<span>ok</span>")

            def log_message(self, *args):
                pass  # keep test output clean

        self.source_mtime_header = source_mtime_header
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_existing_asra_status_is_foreign_when_health_endpoint_returns_a_non_200():
    fake = _FakeHealthServer(status=503)
    try:
        assert main._existing_asra_status("127.0.0.1", fake.port) == "foreign"
    finally:
        fake.close()


def test_existing_asra_status_is_fresh_when_running_code_is_at_least_as_new():
    # A source mtime from far in the future is, by definition, at least as new as this process's
    # own current main.py -- never "stale".
    fake = _FakeHealthServer(source_mtime_header="9999999999.0")
    try:
        assert main._existing_asra_status("127.0.0.1", fake.port) == "fresh"
    finally:
        fake.close()


def test_existing_asra_status_is_fresh_when_the_header_is_missing_entirely():
    # An older ASRA build from before this staleness check existed -- nothing to compare against,
    # so this must default to "fresh" (the prior, unconditional-reuse behavior) rather than
    # blocking startup on ambiguous data.
    fake = _FakeHealthServer(source_mtime_header=None)
    try:
        assert main._existing_asra_status("127.0.0.1", fake.port) == "fresh"
    finally:
        fake.close()


def test_existing_asra_status_is_stale_when_running_code_predates_the_current_file():
    # A source mtime from the deep past is always older than main.py's own real, current mtime.
    fake = _FakeHealthServer(source_mtime_header="1.0")
    try:
        assert main._existing_asra_status("127.0.0.1", fake.port) == "stale"
    finally:
        fake.close()


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_terminate_stale_asra_kills_a_real_process_and_frees_the_port():
    """Real, confirmed incident this guards: an operator restarted ASRA four separate times and
    hit the identical "stale" refusal every time, because nothing anywhere in this project ever
    actually ended the stale process -- every relaunch just rediscovered it and gave up again.
    _terminate_stale_asra is the self-heal step that closes that loop. Uses a REAL subprocess
    holding a REAL listening socket (not a mock) since the whole point of this function is finding
    and killing an actual OS process by the port it holds -- a mocked psutil would validate nothing
    about whether that real mechanism works."""
    port = _free_port()
    proc = subprocess.Popen([
        sys.executable, "-c",
        "import socket, time\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('127.0.0.1', {port}))\n"
        "s.listen(1)\n"
        "time.sleep(60)\n",
    ])
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not main._port_has_live_listener("127.0.0.1", port):
            time.sleep(0.1)
        assert main._port_has_live_listener("127.0.0.1", port) is True, "test subprocess never actually started listening"

        assert main._terminate_stale_asra("127.0.0.1", port) is True
        assert main._port_has_live_listener("127.0.0.1", port) is False
        assert proc.poll() is not None, "the real process should have actually been terminated, not just the socket"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def test_terminate_stale_asra_returns_false_when_nothing_is_listening():
    # No PID bound to the port at all -- nothing to find, nothing to kill, no false claim of success.
    assert main._terminate_stale_asra("127.0.0.1", _free_port()) is False
