"""Nikto: build_nikto_command reliably places -host <target> itself (the model only adds tuning
flags via extra_args, same pattern as whatweb/nmap). Real incident this fixes: nikto rejects a
bare invocation with no -host and dumps its own usage text instead ("ERROR: No host specified"),
exiting 0 -- a real scan session called nikto with empty extra_args and got that usage dump back
as a "success" result, achieving zero real scanning without anyone noticing.
"""
from agent.tools.builders.nikto import build_nikto_command


def test_nikto_is_registered_with_its_own_build_command_not_the_generic_discovered_path():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("nikto")
    assert spec.build_command is build_nikto_command


def test_build_command_places_host_flag_with_the_target():
    command = build_nikto_command({"target": "https://example.com"})
    assert command[0] == "nikto"
    assert "-host" in command
    assert command[command.index("-host") + 1] == "https://example.com"


def test_build_command_appends_extra_args():
    command = build_nikto_command({"target": "https://example.com", "extra_args": ["-Tuning", "1,2,3"]})
    assert "-Tuning" in command
    assert "1,2,3" in command


def test_build_command_never_relies_on_the_model_for_the_target():
    """Even with no extra_args at all, -host must still be present -- the whole point of this
    builder existing instead of the generic discovered-tool path."""
    command = build_nikto_command({"target": "https://example.com"})
    assert "-host" in command


# --- -maxtime: nikto must never rely on the external subprocess hard-kill to end a long scan ---


def test_build_command_adds_a_default_maxtime(monkeypatch):
    monkeypatch.delenv("TOOL_TIMEOUT_SECONDS", raising=False)
    command = build_nikto_command({"target": "https://example.com"})
    assert "-maxtime" in command
    maxtime_value = command[command.index("-maxtime") + 1]
    assert maxtime_value.endswith("s")
    assert int(maxtime_value[:-1]) < 120  # under the runner's own 120s default, with margin to spare


def test_build_command_maxtime_tracks_the_configured_external_timeout(monkeypatch):
    monkeypatch.setenv("TOOL_TIMEOUT_SECONDS", "600")
    command = build_nikto_command({"target": "https://example.com"})
    maxtime_value = command[command.index("-maxtime") + 1]
    assert maxtime_value == "570s"  # 600 - the 30s safety margin


def test_build_command_maxtime_never_goes_below_the_floor(monkeypatch):
    monkeypatch.setenv("TOOL_TIMEOUT_SECONDS", "10")
    command = build_nikto_command({"target": "https://example.com"})
    maxtime_value = command[command.index("-maxtime") + 1]
    assert maxtime_value == "30s"  # floor, not a near-zero/negative value


def test_build_command_does_not_double_up_when_the_model_already_set_maxtime():
    command = build_nikto_command({"target": "https://example.com", "extra_args": ["-maxtime", "45s"]})
    assert command.count("-maxtime") == 1
    assert command[command.index("-maxtime") + 1] == "45s"
