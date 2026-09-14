"""make_generic_discovered_command (agent/tools/builders/discovered.py): every auto-discovered or
custom tool (httpx, nikto's own convention-differing cousins, etc.) builds its command as
[executable, *extra_args] -- params["target"] is deliberately NOT auto-appended, since every real
tool uses a different flag for it (-u, -h, -l, a bare positional, ...) and there is no single
convention to guess.

Real incident this file covers: confirmed live, a model called httpx 5 separate times in one real
session with target set but NEVER referenced anywhere in extra_args -- httpx ran every single time
with nothing to actually scan, silently exited 0 with empty stdout (no error at all), and the
model's own postmortem wrongly blamed "environment limitations" for what was actually its own
missed flag, five times over, with nothing catching it. Fixed with a deterministic check: target
(or its scheme-stripped core) must appear somewhere in extra_args, or build_command raises a clear,
actionable, retryable error instead of silently building a target-less command.
"""
import pytest

from agent.tools.builders.discovered import make_generic_discovered_command


def test_builds_executable_plus_extra_args_when_target_is_referenced():
    build = make_generic_discovered_command("httpx")
    command = build({"target": "https://example.com", "extra_args": ["-u", "https://example.com", "-silent"]})
    assert command == ["httpx", "-u", "https://example.com", "-silent"]


def test_raises_when_target_is_given_but_never_referenced_in_extra_args():
    """The exact real incident: target set, extra_args has real flags, but none of them actually
    carry the target anywhere -- must be a clear, actionable error, not a silent no-op command."""
    build = make_generic_discovered_command("httpx")
    with pytest.raises(ValueError, match="never appears anywhere in extra_args"):
        build({"target": "https://juice-shop.herokuapp.com", "extra_args": ["-title", "-server", "-tech-detect"]})


def test_raises_when_target_is_given_with_completely_empty_extra_args():
    build = make_generic_discovered_command("httpx")
    with pytest.raises(ValueError, match="never appears anywhere in extra_args"):
        build({"target": "https://example.com"})


def test_accepts_a_bare_hostname_target_matching_a_full_url_in_extra_args():
    """target is often given as a bare host while extra_args carries the full scheme+path --
    matching on the scheme-stripped core (not an exact string match) must still succeed."""
    build = make_generic_discovered_command("nikto")
    command = build({"target": "example.com", "extra_args": ["-h", "https://example.com/", "-Tuning", "1"]})
    assert command == ["nikto", "-h", "https://example.com/", "-Tuning", "1"]


def test_no_target_at_all_is_never_an_error_extra_args_only_tools_still_work():
    """Some tools are called with no target field at all (e.g. a bare informational command) --
    this validation only ever fires when target is actually SET but unreferenced, never when it's
    simply absent."""
    build = make_generic_discovered_command("subfinder")
    command = build({"extra_args": ["-d", "example.com", "-silent"]})
    assert command == ["subfinder", "-d", "example.com", "-silent"]
