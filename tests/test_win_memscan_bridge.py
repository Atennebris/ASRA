"""agent/tools/win_memscan_bridge.py -- the Windows live-memory bridge client. Mocked at the
_send/_read_bridge_info boundary, same style tests/test_ghidra_builder.py uses for that module's
own persistent-server bridge: never a raw socket, never a real desktop-shell process.
"""
from __future__ import annotations

from unittest.mock import patch

from agent.tools import win_memscan_bridge as bridge


def test_unavailable_when_no_bridge_info_file(tmp_path):
    with patch.object(bridge, "_read_bridge_info", return_value=None):
        result = bridge.attach("sess", 1234, "int32")
    assert result["status"] == "error"
    assert "desktop app" in result["error"]


def test_attach_sends_the_right_request_and_returns_the_response():
    info = {"port": 47219, "token": "tok", "hosts": ["172.22.144.1"]}
    sent = {}

    def fake_send(host, port, request):
        sent["host"], sent["port"], sent["request"] = host, port, request
        return {"status": "ok", "scan_id": "win1", "pid": 1234, "scan_data_type": "int32"}

    with patch.object(bridge, "_read_bridge_info", return_value=info), patch.object(bridge, "_send", side_effect=fake_send):
        result = bridge.attach("sess", 1234, "int32")

    assert result == {"status": "ok", "scan_id": "win1", "pid": 1234, "scan_data_type": "int32"}
    assert sent["host"] == "172.22.144.1"
    assert sent["port"] == 47219
    assert sent["request"]["mode"] == "attach"
    assert sent["request"]["token"] == "tok"
    assert sent["request"]["pid"] == 1234
    assert sent["request"]["scan_data_type"] == "int32"


def test_attach_rejects_a_non_integer_pid():
    result = bridge.attach("sess", "not-a-pid", "int32")
    assert result["status"] == "error"
    assert "pid must be an integer" in result["error"]


def test_tries_each_host_in_order_and_caches_the_first_one_that_works():
    info = {"port": 47219, "token": "tok", "hosts": ["127.0.0.1", "172.22.144.1"]}
    attempts = []

    def fake_send(host, port, request):
        attempts.append(host)
        if host == "127.0.0.1":
            raise OSError("connection refused")
        return {"status": "ok"}

    with patch.object(bridge, "_read_bridge_info", return_value=info), patch.object(bridge, "_send", side_effect=fake_send):
        bridge._cached_host = None
        bridge._cached_port = None
        result = bridge.scan("sess", "win1", "exact", 42)

    assert result == {"status": "ok"}
    assert attempts == ["127.0.0.1", "172.22.144.1"]


def test_all_hosts_unreachable_reports_a_clear_error():
    info = {"port": 47219, "token": "tok", "hosts": ["127.0.0.1"]}
    with patch.object(bridge, "_read_bridge_info", return_value=info), patch.object(bridge, "_send", side_effect=OSError("refused")):
        bridge._cached_host = None
        bridge._cached_port = None
        result = bridge.list_matches("sess", "win1")
    assert result["status"] == "error"
    assert "desktop app" in result["error"]


def test_write_rejects_a_non_integer_list_index():
    result = bridge.write("sess", "win1", "not-an-index", 1)
    assert result["status"] == "error"
    assert "list_index must be an integer" in result["error"]


def test_list_matches_truncates_to_the_requested_limit():
    info = {"port": 47219, "token": "tok", "hosts": ["172.22.144.1"]}
    matches = [{"index": i, "address": hex(i), "value": i} for i in range(10)]

    with patch.object(bridge, "_read_bridge_info", return_value=info), patch.object(
        bridge, "_send", return_value={"status": "ok", "matches": matches, "total_count": 10}
    ):
        bridge._cached_host, bridge._cached_port = "172.22.144.1", 47219
        result = bridge.list_matches("sess", "win1", limit=3)

    assert len(result["matches"]) == 3
    assert result["total_count"] == 10


def test_bridge_available_reflects_info_file_presence(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    import projects.paths as paths
    paths.resolve_global_app_dir.cache_clear()

    assert bridge.bridge_available() is False
    (tmp_path / "mem_bridge.json").write_text("{}")
    assert bridge.bridge_available() is True
    paths.resolve_global_app_dir.cache_clear()


def test_detach_sends_detach_mode():
    info = {"port": 47219, "token": "tok", "hosts": ["172.22.144.1"]}
    sent = {}

    def fake_send(host, port, request):
        sent.update(request)
        return {"status": "ok"}

    with patch.object(bridge, "_read_bridge_info", return_value=info), patch.object(bridge, "_send", side_effect=fake_send):
        bridge._cached_host, bridge._cached_port = "172.22.144.1", 47219
        bridge.detach("sess", "win1")

    assert sent["mode"] == "detach"
    assert sent["scan_id"] == "win1"
