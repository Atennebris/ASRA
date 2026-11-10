"""build_adb_command/parse_adb_output -- adb (Android live-device/emulator access). Confirmed live
this session against the real CLI (platform-tools 34.0.4) for command shape and output format,
including the real, confirmed-live finding that `adb logcat -d` with no device attached HANGS
(rather than erroring fast the way `adb devices` does) -- not exercised live in this test suite,
only on mocks, for exactly that reason.
"""
from __future__ import annotations

import pytest

from agent.tools.builders.adb import build_adb_command, parse_adb_output


# --- build_adb_command -----------------------------------------------------------------------


def test_devices_is_the_default_mode():
    assert build_adb_command({}) == ["adb", "devices", "-l"]


def test_shell_requires_a_command():
    with pytest.raises(ValueError, match="requires a 'command'"):
        build_adb_command({"mode": "shell"})


def test_shell_command_shape():
    assert build_adb_command({"mode": "shell", "command": "ls /sdcard"}) == ["adb", "shell", "ls /sdcard"]


def test_install_requires_an_apk_path():
    with pytest.raises(ValueError, match="requires an 'apk_path'"):
        build_adb_command({"mode": "install"})


def test_install_does_not_replace_by_default():
    command = build_adb_command({"mode": "install", "apk_path": "/tmp/app.apk"})
    assert command == ["adb", "install", "/tmp/app.apk"]


def test_install_replace_is_opt_in():
    command = build_adb_command({"mode": "install", "apk_path": "/tmp/app.apk", "replace": True})
    assert command == ["adb", "install", "-r", "/tmp/app.apk"]


def test_pull_requires_a_remote_path():
    with pytest.raises(ValueError, match="requires a 'remote_path'"):
        build_adb_command({"mode": "pull"})


def test_pull_with_only_remote_path():
    assert build_adb_command({"mode": "pull", "remote_path": "/sdcard/file.txt"}) == ["adb", "pull", "/sdcard/file.txt"]


def test_pull_with_local_path():
    command = build_adb_command({"mode": "pull", "remote_path": "/sdcard/file.txt", "local_path": "/tmp/out.txt"})
    assert command == ["adb", "pull", "/sdcard/file.txt", "/tmp/out.txt"]


def test_logcat_always_dumps_and_exits():
    command = build_adb_command({"mode": "logcat"})
    assert command == ["adb", "logcat", "-d"]


def test_logcat_with_filter():
    command = build_adb_command({"mode": "logcat", "filter": "*:E"})
    assert command == ["adb", "logcat", "-d", "*:E"]


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="Unknown adb mode"):
        build_adb_command({"mode": "explode"})


def test_shell_command_rejects_control_characters():
    with pytest.raises(ValueError):
        build_adb_command({"mode": "shell", "command": "ls\nrm -rf /"})


# --- parse_adb_output -------------------------------------------------------------------------


def test_parse_devices_with_none_connected():
    result = parse_adb_output("List of devices attached\n")
    assert result["devices"] == []


def test_parse_devices_with_a_real_device():
    stdout = "List of devices attached\nABCD1234       device usb:1-1 product:x model:y"
    result = parse_adb_output(stdout)
    assert result["devices"] == [{"serial": "ABCD1234", "detail": "device usb:1-1 product:x model:y"}]


def test_parse_shell_output_has_no_devices_key():
    result = parse_adb_output("uid=2000(shell) gid=2000(shell)\n")
    assert "devices" not in result
    assert result["raw_output"] == "uid=2000(shell) gid=2000(shell)"
