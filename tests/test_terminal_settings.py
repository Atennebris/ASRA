"""Standalone Terminal tab's own tiny settings store (agent/tools/terminal_settings.py) -- the
middle-click close confirmation's "don't ask again" checkbox. Deliberately in-memory only (no
on-disk file at all): a direct, explicit operator instruction is that this flag resets back to
"ask again" on every ASRA process restart, and only ever persists across a plain browser
reload/tab-switch within that SAME running server -- the opposite of what an earlier, file-backed
version of this module did.
"""
from __future__ import annotations

from agent.tools import terminal_settings


def setup_function():
    # Reset the module-level flag before every test -- it's real process-wide state now (that's
    # the whole point), so tests need their own explicit isolation instead of relying on a fresh
    # file per test the way the old on-disk version could.
    terminal_settings._skip_close_confirm = False


def teardown_function():
    # Also reset on the way out -- this flag is shared across every OTHER test file in the same
    # pytest run too (tests/test_terminal_routes.py has its own matching reset for the same
    # reason), not just within this one.
    terminal_settings._skip_close_confirm = False


def test_defaults_to_not_skipping_the_confirmation():
    assert terminal_settings.load_terminal_settings() == {"skip_close_confirm": False}


def test_save_and_reload_round_trips():
    terminal_settings.save_skip_close_confirm(True)
    assert terminal_settings.load_terminal_settings() == {"skip_close_confirm": True}

    terminal_settings.save_skip_close_confirm(False)
    assert terminal_settings.load_terminal_settings() == {"skip_close_confirm": False}


def test_resets_to_default_on_a_fresh_module_state():
    """Simulates "kill ASRA entirely and relaunch" -- there is no persistence mechanism at all to
    read back from, so a fresh process (a fresh value of the module-level flag, exactly what
    Python itself gives a newly imported module) always starts at the same default, regardless of
    what was saved before. This is the one behavior the operator specifically asked for after an
    earlier, file-backed version of this module got it backwards."""
    terminal_settings.save_skip_close_confirm(True)
    assert terminal_settings.load_terminal_settings()["skip_close_confirm"] is True

    # What a real process restart amounts to here: the module-level variable back at its own
    # class-body default, nothing read from anywhere.
    terminal_settings._skip_close_confirm = False
    assert terminal_settings.load_terminal_settings() == {"skip_close_confirm": False}


def test_survives_within_the_same_process_regardless_of_caller():
    """The one thing that SHOULD carry over -- a plain browser reload/tab-switch within the same
    running server is just another call into this same module, not a process restart, so the
    flag must still read back correctly."""
    terminal_settings.save_skip_close_confirm(True)
    # Simulates a totally separate request handler reading it back later, same running process.
    assert terminal_settings.load_terminal_settings()["skip_close_confirm"] is True
