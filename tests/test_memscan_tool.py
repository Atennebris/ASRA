"""agent/tools/memscan_manager.py -- the memscan_* live-process memory-scan/patch tools.

Real subprocess.Popen (a real scanmem process) is never invoked here -- these are unit tests of
the manager's own guard rails and protocol logic, not an integration test against the real tool
(that's the plan's own separate live-verification step, run once against a real WSL2 install).

The single most important thing under test: every value this module sends to a live scanmem
process MUST be a strictly-validated plain number -- scanmem's own REPL has a `shell` command
("execute a shell command without leaving scanmem", confirmed live via `help`), so anything less
strict than an anchored numeric-only regex would be an arbitrary-command-execution hole.
"""
import os
import threading

import pytest

import agent.tools.memscan_manager as memscan

# memscan_* (scanmem) is a Linux-only, /proc-based tool -- no Darwin branch anywhere in this
# feature (setup_tools.sh's own install_scanmem warns and returns 1 on macOS), so these tests
# (several of which genuinely enumerate /proc for a real pid) are skipped outright on any other
# platform rather than failing for an unrelated reason.
pytestmark = pytest.mark.skipif(not os.path.isdir("/proc"), reason="memscan_manager (scanmem) is Linux-only")


class _FakeSession:
    """A test double standing in for a real _ScanSession -- records every command sent instead of
    talking to a real scanmem process, and returns canned drain() output in order."""

    def __init__(self, drain_responses=None):
        self.lock = threading.Lock()
        self.sent_commands: list[str] = []
        self._drain_responses = list(drain_responses or [])
        self.last_activity = 0.0
        self.pid = 4242
        self.scan_data_type = "int32"
        self._alive = True

    def send(self, command: str) -> None:
        self.sent_commands.append(command)

    def drain(self, settle_seconds: float) -> str:
        if self._drain_responses:
            return self._drain_responses.pop(0)
        return ""

    def is_alive(self) -> bool:
        return self._alive


@pytest.fixture(autouse=True)
def _clean_sessions():
    """Every test gets a pristine module-level session registry -- these tests directly poke
    memscan._SESSIONS (a module-level dict) rather than going through attach()'s own real Popen
    spawn, so leftover state from one test must never leak into the next."""
    memscan._SESSIONS.clear()
    yield
    memscan._SESSIONS.clear()


def _install_fake_session(session_id: str, scan_id: str, drain_responses=None) -> _FakeSession:
    fake = _FakeSession(drain_responses)
    memscan._SESSIONS.setdefault(session_id, {})[scan_id] = fake
    return fake


# --- _validate_numeric: the critical safety boundary ----------------------------------------------

@pytest.mark.parametrize("value", ["100", "-100", "0x1A", "3.14", "-3.14", "0"])
def test_validate_numeric_accepts_plain_numbers(value):
    assert memscan._validate_numeric(value) == value


@pytest.mark.parametrize("value", [
    "5; shell id",
    "5\nshell id",
    "shell rm -rf /",
    "100 200",
    "",
    "abc",
    "5;exit",
    "0x1A; shell id",
])
def test_validate_numeric_rejects_anything_that_is_not_a_bare_number(value):
    with pytest.raises(ValueError):
        memscan._validate_numeric(value)


def test_scan_mode_exact_rejects_a_non_numeric_value_before_sending_anything():
    fake = _install_fake_session("sess1", "scan1")
    result = memscan.scan("sess1", "scan1", "exact", "5; shell id")
    assert result["status"] == "error"
    assert fake.sent_commands == []  # never reached the live scanmem process at all


def test_write_rejects_a_non_numeric_value_before_sending_anything():
    fake = _install_fake_session("sess1", "scan1")
    result = memscan.write("sess1", "scan1", 0, "5; shell id")
    assert result["status"] == "error"
    assert fake.sent_commands == []


# --- write(): must go through `set <index>=<value>`, never a raw address ---------------------------

def test_write_sends_set_by_index_not_a_raw_address_write_command():
    fake = _install_fake_session("sess1", "scan1")
    result = memscan.write("sess1", "scan1", 2, 999)
    assert result["status"] == "ok"
    assert fake.sent_commands == ["set 2=999"]
    assert not any(cmd.startswith("write ") for cmd in fake.sent_commands)


def test_write_rejects_a_negative_list_index():
    fake = _install_fake_session("sess1", "scan1")
    result = memscan.write("sess1", "scan1", -1, 999)
    assert result["status"] == "error"
    assert fake.sent_commands == []


# --- scan(): mode -> command mapping, confirmed live via a real scanmem session -------------------

def test_scan_mode_unknown_sends_snapshot():
    fake = _install_fake_session("sess1", "scan1")
    memscan.scan("sess1", "scan1", "unknown")
    assert fake.sent_commands == ["snapshot"]


def test_scan_mode_exact_sends_the_bare_value():
    fake = _install_fake_session("sess1", "scan1")
    memscan.scan("sess1", "scan1", "exact", 100)
    assert fake.sent_commands == ["100"]


@pytest.mark.parametrize("mode,token", [
    ("increased", "+"), ("decreased", "-"), ("changed", "!="), ("unchanged", "="),
])
def test_scan_comparison_modes_send_the_bare_operator_with_no_value(mode, token):
    fake = _install_fake_session("sess1", "scan1")
    memscan.scan("sess1", "scan1", mode)
    assert fake.sent_commands == [token]


def test_scan_comparison_mode_with_a_value_appends_it_to_the_operator():
    fake = _install_fake_session("sess1", "scan1")
    memscan.scan("sess1", "scan1", "increased", 5)
    assert fake.sent_commands == ["+ 5"]


def test_scan_exact_without_a_value_is_an_error():
    fake = _install_fake_session("sess1", "scan1")
    result = memscan.scan("sess1", "scan1", "exact")
    assert result["status"] == "error"
    assert fake.sent_commands == []


# --- scan(): string/bytearray scan_data_type -- confirmed live against a real scanmem 0.17 session
# (a real Python process holding a known string/byte marker in memory, attached to and searched for
# by a real scanmem, not assumed from --help alone). VALUE_TYPES used to expose only the six numeric
# types; scanmem's own `option scan_data_type` genuinely also accepts "string" and "bytearray".

def test_scan_exact_string_sends_the_quote_prefixed_command():
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = "string"
    memscan.scan("sess1", "scan1", "exact", "ACCESS GRANTED")
    assert fake.sent_commands == ['" ACCESS GRANTED']


def test_scan_exact_string_rejects_a_newline_before_sending_anything():
    """The critical injection boundary for the new string type -- a newline in the value would land
    as a genuinely separate line on scanmem's own stdin (one command per line), which could smuggle
    a real second scanmem command (its own `shell` command included) in behind the string search."""
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = "string"
    result = memscan.scan("sess1", "scan1", "exact", "ACCESS GRANTED\nshell rm -rf /")
    assert result["status"] == "error"
    assert fake.sent_commands == []


def test_scan_exact_string_rejects_empty_value():
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = "string"
    result = memscan.scan("sess1", "scan1", "exact", "")
    assert result["status"] == "error"
    assert fake.sent_commands == []


def test_scan_exact_bytearray_sends_the_bare_hex_pattern():
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = "bytearray"
    memscan.scan("sess1", "scan1", "exact", "FF ?? EE ?? 02 01")
    assert fake.sent_commands == ["FF ?? EE ?? 02 01"]


@pytest.mark.parametrize("bad_pattern", ["FF;shell id", "FF,EE", "GG", "FF  EE", "FF\nshell id", ""])
def test_scan_exact_bytearray_rejects_malformed_patterns(bad_pattern):
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = "bytearray"
    result = memscan.scan("sess1", "scan1", "exact", bad_pattern)
    assert result["status"] == "error"
    assert fake.sent_commands == []


@pytest.mark.parametrize("data_type", ["string", "bytearray"])
@pytest.mark.parametrize("mode", ["increased", "decreased"])
def test_scan_increased_decreased_rejected_for_non_ordered_types(data_type, mode):
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = data_type
    result = memscan.scan("sess1", "scan1", mode)
    assert result["status"] == "error"
    assert fake.sent_commands == []


@pytest.mark.parametrize("data_type", ["string", "bytearray"])
@pytest.mark.parametrize("mode,token", [("changed", "!="), ("unchanged", "=")])
def test_scan_changed_unchanged_with_no_value_still_works_for_non_ordered_types(data_type, mode, token):
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = data_type
    result = memscan.scan("sess1", "scan1", mode)
    assert result["status"] != "error"
    assert fake.sent_commands == [token]


def test_scan_changed_with_a_value_rejected_for_string_type():
    fake = _install_fake_session("sess1", "scan1")
    fake.scan_data_type = "string"
    result = memscan.scan("sess1", "scan1", "changed", "ACCESS GRANTED")
    assert result["status"] == "error"
    assert fake.sent_commands == []


def test_scan_parses_match_count_from_real_scanmem_output():
    _install_fake_session("sess1", "scan1", drain_responses=[
        "info: maps file located at /proc/798/maps opened.\n"
        "info: 6 suitable regions found.\n"
        "info: we currently have 2 matches.\n"
    ])
    result = memscan.scan("sess1", "scan1", "exact", 100)
    assert result["match_count"] == 2


def test_scan_parses_single_match_identified_message():
    """scanmem's own wording switches to \"match identified\" (no explicit count) once exactly one
    match remains -- confirmed live -- must still report match_count=1, not None."""
    _install_fake_session("sess1", "scan1", drain_responses=[
        "info: we currently have 1 matches.\n"
        "info: match identified, use \"set\" to modify value.\n"
    ])
    result = memscan.scan("sess1", "scan1", "exact", 424242)
    assert result["match_count"] == 1


def test_scan_against_an_unknown_scan_id_is_an_error():
    result = memscan.scan("sess1", "does-not-exist", "exact", 100)
    assert result["status"] == "error"


# --- list_matches(): real captured scanmem `list` output format ------------------------------------

# The exact line format confirmed live against a real scanmem 0.17 session (see the plan's own live
# verification), including the trailing space inside "[I32 ]" -- not a hypothetical shape.
_REAL_LIST_LINE = "[ 0] 7fffa95da628,  5 +        1e628, stack, 424242, [I32 ]"


def test_list_matches_parses_a_real_captured_scanmem_line():
    _install_fake_session("sess1", "scan1", drain_responses=["", _REAL_LIST_LINE + "\n"])
    result = memscan.list_matches("sess1", "scan1")
    assert result["status"] == "ok"
    assert result["matches"] == [{
        "index": 0, "address": "7fffa95da628", "region": "stack", "value": "424242", "type": "I32",
    }]
    assert result["total_count"] == 1
    assert result["truncated"] is False


def test_list_matches_sends_update_before_list_to_get_fresh_values():
    fake = _install_fake_session("sess1", "scan1", drain_responses=["", ""])
    memscan.list_matches("sess1", "scan1")
    assert fake.sent_commands == ["update", "list"]


def test_list_matches_caps_at_the_configured_limit_with_an_honest_total_count():
    lines = "\n".join(f"[ {i}] deadbeef{i:04x}, 5 + {i:x}, stack, 100, [I32 ]" for i in range(memscan._MAX_LIST_ENTRIES + 5))
    _install_fake_session("sess1", "scan1", drain_responses=["", lines])
    result = memscan.list_matches("sess1", "scan1")
    assert len(result["matches"]) == memscan._MAX_LIST_ENTRIES
    assert result["total_count"] == memscan._MAX_LIST_ENTRIES + 5
    assert result["truncated"] is True


# --- attach(): pid/type safety guards, before any real Popen would ever be spawned -----------------

def test_attach_refuses_own_pid():
    result = memscan.attach("sess1", os.getpid(), "int32")
    assert result["status"] == "error"
    assert "pid" in result["error"]


def test_attach_refuses_parent_pid():
    result = memscan.attach("sess1", os.getppid(), "int32")
    assert result["status"] == "error"


def test_attach_refuses_low_numbered_system_pid():
    result = memscan.attach("sess1", 1, "int32")
    assert result["status"] == "error"


def test_attach_refuses_a_nonexistent_pid():
    # A pid that (almost certainly) doesn't exist on this machine -- /proc/<pid> won't be a directory.
    result = memscan.attach("sess1", 999999, "int32")
    assert result["status"] == "error"
    assert "no such process" in result["error"]


def test_attach_refuses_an_unknown_scan_data_type():
    result = memscan.attach("sess1", 999999, "not_a_real_type")
    assert result["status"] == "error"
    assert "scan_data_type" in result["error"]


def test_attach_spawns_a_real_session_and_sets_scan_data_type(monkeypatch):
    monkeypatch.setattr(memscan.subprocess, "Popen", lambda *a, **k: _FakePopenForAttach())
    result = memscan.attach("sess1", _a_real_pid_thats_not_self_or_parent(), "float64")
    assert result["status"] == "ok"
    session = memscan._SESSIONS["sess1"][result["scan_id"]]
    assert "option scan_data_type float64\n" in session.popen.stdin.written


class _FakePopenForAttach:
    """Minimal stand-in for subprocess.Popen used only by the attach()-spawns-a-real-session test
    below -- stdin/stdout are simple in-memory objects so _ScanSession's own reader thread and
    send()/drain() calls have something to operate on without a real scanmem binary."""

    def __init__(self):
        self.stdin = _FakeStdinBuffer()
        self.stdout = iter(())  # reader thread's `for line in stdout` ends immediately -- fine, no output expected in this test
        self._terminated = False

    def poll(self):
        return None if not self._terminated else 0

    def terminate(self):
        self._terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self._terminated = True


class _FakeStdinBuffer:
    def __init__(self):
        self.written: list[str] = []

    def write(self, text: str) -> None:
        self.written.append(text)

    def flush(self) -> None:
        pass


def _a_real_pid_thats_not_self_or_parent() -> int:
    # pid 1 (init/systemd) always exists on a real Linux box and is never this test process's own
    # pid or its direct parent -- deliberately excluded by attach()'s own low-pid guard though, so
    # this can't just be 1; the test process's own /proc namespace always has SOMETHING besides
    # itself and its parent running (the OS itself), so scan /proc for the first candidate.
    import os as _os
    self_pid, parent_pid = _os.getpid(), _os.getppid()
    for entry in _os.listdir("/proc"):
        if entry.isdigit():
            candidate = int(entry)
            if candidate >= 10 and candidate not in (self_pid, parent_pid):
                return candidate
    pytest.skip("no other real process found under /proc to attach a fake session to")


def test_attach_respects_the_max_concurrent_sessions_cap(monkeypatch):
    monkeypatch.setenv("MEMSCAN_MAX_CONCURRENT_SESSIONS", "1")
    _install_fake_session("sess1", "existing-scan")
    # attach()'s own capacity check runs BEFORE the /proc/<pid> existence check (see that
    # function's own comment), so any non-self/parent/low-numbered pid hits "skipped" here without
    # ever needing to be a real running process.
    result = memscan.attach("sess1", 999999, "int32")
    assert result["status"] == "skipped"


# --- detach() / kill_all(): the explicit cleanup path -----------------------------------------

def test_detach_sends_exit_and_removes_the_session():
    fake = _install_fake_session("sess1", "scan1")
    result = memscan.detach("sess1", "scan1")
    assert result["status"] == "ok"
    assert fake.sent_commands == ["exit"]
    assert "scan1" not in memscan._SESSIONS.get("sess1", {})


def test_detach_an_already_gone_scan_id_is_an_error():
    result = memscan.detach("sess1", "does-not-exist")
    assert result["status"] == "error"


def test_kill_all_terminates_every_session_for_one_asra_session_only():
    fake_a1 = _install_fake_session("sess1", "scan-a")
    fake_a2 = _install_fake_session("sess1", "scan-b")
    fake_b1 = _install_fake_session("sess2", "scan-c")

    memscan.kill_all("sess1")

    assert "sess1" not in memscan._SESSIONS
    assert fake_a1.sent_commands == ["exit"]
    assert fake_a2.sent_commands == ["exit"]
    # A different ASRA project's own memscan session must be completely untouched.
    assert "sess2" in memscan._SESSIONS
    assert fake_b1.sent_commands == []


# --- idle reaper: _sweep_idle_sessions()'s own staleness math, no real waiting/threading needed ---

def test_sweep_idle_sessions_removes_only_sessions_past_the_idle_timeout(monkeypatch):
    import time as time_module

    monkeypatch.setenv("MEMSCAN_SESSION_IDLE_TIMEOUT_SECONDS", "60")
    stale = _install_fake_session("sess1", "stale-scan")
    stale.last_activity = time_module.time() - 120  # 2 minutes idle, past the 60s timeout
    fresh = _install_fake_session("sess1", "fresh-scan")
    fresh.last_activity = time_module.time()  # just used

    removed = memscan._sweep_idle_sessions()

    assert removed == [stale]
    assert "stale-scan" not in memscan._SESSIONS["sess1"]
    assert "fresh-scan" in memscan._SESSIONS["sess1"]


def test_sweep_idle_sessions_drops_the_empty_session_entry_entirely():
    stale = _install_fake_session("sess1", "only-scan")
    stale.last_activity = 0.0  # ancient -- guaranteed past any real timeout

    memscan._sweep_idle_sessions()

    assert "sess1" not in memscan._SESSIONS
