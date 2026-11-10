"""build_sigrok_cli_command/parse_sigrok_cli_output -- sigrok-cli (logic-signal capture). See that
module's own docstring for the honest hardware caveat: mode="capture" against anything but the
built-in "demo" driver needs a real, physically connected device this test suite cannot provide --
confirmed live this session against the real CLI (v0.7.2) for command shape and output format.
"""
from __future__ import annotations

import pytest

from agent.tools.builders.sigrok_cli import build_sigrok_cli_command, parse_sigrok_cli_output


# --- build_sigrok_cli_command -----------------------------------------------------------------


def test_scan_is_the_default_mode():
    assert build_sigrok_cli_command({}) == ["sigrok-cli", "--scan"]


def test_scan_mode_explicit():
    assert build_sigrok_cli_command({"mode": "scan"}) == ["sigrok-cli", "--scan"]


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="Unknown sigrok-cli mode"):
        build_sigrok_cli_command({"mode": "explode"})


def test_capture_requires_a_driver():
    with pytest.raises(ValueError, match="requires a 'driver'"):
        build_sigrok_cli_command({"mode": "capture"})


def test_capture_default_time_when_neither_time_nor_samples_given():
    command = build_sigrok_cli_command({"mode": "capture", "driver": "demo"})
    assert command[:3] == ["sigrok-cli", "-d", "demo"]
    assert "--time" in command


def test_capture_with_explicit_time_ms():
    command = build_sigrok_cli_command({"mode": "capture", "driver": "demo", "time_ms": 500})
    assert command == ["sigrok-cli", "-d", "demo", "--time", "500"]


def test_capture_with_explicit_samples():
    command = build_sigrok_cli_command({"mode": "capture", "driver": "demo", "samples": 1000})
    assert command == ["sigrok-cli", "-d", "demo", "--samples", "1000"]


def test_capture_rejects_both_time_and_samples_together():
    with pytest.raises(ValueError, match="either 'time_ms' or 'samples'"):
        build_sigrok_cli_command({"mode": "capture", "driver": "demo", "time_ms": 500, "samples": 1000})


def test_capture_with_channels():
    command = build_sigrok_cli_command({"mode": "capture", "driver": "demo", "channels": "D0,D1", "time_ms": 100})
    assert "-C" in command
    assert "D0,D1" in command


@pytest.mark.parametrize("bad_time", ["not-a-number", -5, 0])
def test_capture_rejects_a_bad_time_ms(bad_time):
    with pytest.raises(ValueError):
        build_sigrok_cli_command({"mode": "capture", "driver": "demo", "time_ms": bad_time})


@pytest.mark.parametrize("bad_samples", ["not-a-number", -5, 0])
def test_capture_rejects_bad_samples(bad_samples):
    with pytest.raises(ValueError):
        build_sigrok_cli_command({"mode": "capture", "driver": "demo", "samples": bad_samples})


def test_driver_rejects_control_characters():
    with pytest.raises(ValueError):
        build_sigrok_cli_command({"mode": "capture", "driver": "demo\nrm -rf /"})


# --- parse_sigrok_cli_output --------------------------------------------------------------------


def test_parse_scan_output_structures_devices():
    stdout = "The following devices were found:\ndemo - Demo device with 13 channels: D0 D1 D2"
    result = parse_sigrok_cli_output(stdout)
    assert result["devices"] == [{"driver": "demo", "description": "Demo device with 13 channels: D0 D1 D2"}]
    assert result["raw_output"] == stdout


def test_parse_scan_output_no_devices_found():
    stdout = "No devices found."
    result = parse_sigrok_cli_output(stdout)
    assert "devices" not in result
    assert result["raw_output"] == stdout


def test_parse_capture_output_has_no_devices_key():
    # Confirmed live shape: capture output is per-channel bitstream lines, never "<driver> - ..."
    stdout = "libsigrok 0.5.2\nAcquisition with 8/13 channels at 200 kHz\nD0:10001111 00001111"
    result = parse_sigrok_cli_output(stdout)
    assert "devices" not in result
    assert result["raw_output"] == stdout
