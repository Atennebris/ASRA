"""agent/tools/sandbox.py: operator-Stop reachability for run_with_process_group_timeout.

The bug these guard: strace/wine run through run_with_process_group_timeout (a process-group leader
spawned with start_new_session=True), but it did NOT register its process into
runner.current_subprocess_registry the way Tier-2 tools do -- so agent/core.py's _dispatch_tool
CancelledError handler (the operator clicking Stop) could not reach it, and a hung wine ran orphaned
until its own timeout. The fix registers a group-kill handle there; these tests pin that it is
registered during the run, discarded after, and that the handle kills the whole GROUP (not just the
leader) so wine's children die with it.
"""
import signal

from agent.tools import sandbox
from agent.tools.runner import current_subprocess_registry


class _RecordingRegistry(set):
    """A set that remembers everything add()-ed to it, so a test can prove the handle was present
    DURING the run even though it is discarded by the time the call returns."""

    def __init__(self):
        super().__init__()
        self.ever_added = []

    def add(self, item):
        self.ever_added.append(item)
        super().add(item)


def test_registers_kill_handle_during_run_and_discards_after():
    registry = _RecordingRegistry()
    token = current_subprocess_registry.set(registry)
    try:
        result = sandbox.run_with_process_group_timeout(["echo", "hi"], timeout_seconds=5)
    finally:
        current_subprocess_registry.reset(token)

    assert result.returncode == 0
    # Exactly one handle was registered while the child ran...
    assert len(registry.ever_added) == 1
    assert isinstance(registry.ever_added[0], sandbox._ProcessGroupKillHandle)
    # ...and it was discarded on the way out, so nothing lingers in the registry afterward.
    assert len(registry) == 0


def test_no_registry_set_runs_normally_and_registers_nothing():
    # A direct, non-dispatch call has no registry in context -- behavior must be byte-identical to
    # before the fix: run completes, nothing to register.
    token = current_subprocess_registry.set(None)
    try:
        result = sandbox.run_with_process_group_timeout(["echo", "hi"], timeout_seconds=5)
    finally:
        current_subprocess_registry.reset(token)

    assert result.returncode == 0


def test_kill_handle_signals_the_whole_process_group(monkeypatch):
    class _FakeProc:
        pid = 4242

    killed = {}
    monkeypatch.setattr(sandbox.os, "getpgid", lambda pid: pid + 1000)  # a distinct pgid
    monkeypatch.setattr(sandbox.os, "killpg", lambda pgid, sig: killed.setdefault("call", (pgid, sig)))

    sandbox._ProcessGroupKillHandle(_FakeProc()).kill()

    # os.killpg on the GROUP (getpgid of the leader), not Popen.kill() on just the leader -- so
    # wine's children (wineserver) die too, the whole point of the handle over a bare Popen.
    assert killed["call"] == (5242, signal.SIGKILL)


def test_kill_handle_swallows_already_dead_group(monkeypatch):
    class _FakeProc:
        pid = 4242

    def _raise_gone(pid):
        raise ProcessLookupError

    monkeypatch.setattr(sandbox.os, "getpgid", _raise_gone)

    # A group that already exited between registration and Stop must not raise out of .kill() --
    # _dispatch_tool's loop guards ProcessLookupError too, but the handle owns its own guard.
    sandbox._ProcessGroupKillHandle(_FakeProc()).kill()
