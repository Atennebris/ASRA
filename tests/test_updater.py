"""Unit tests for agent/updater.py -- git interaction fully mocked (no real repo/network)."""
import agent.updater as updater


def _responder(overrides=None):
    """Build a fake _git that returns canned (code, stdout, stderr) per argument tuple. Defaults
    describe a clean, up-to-date checkout; pass overrides to model other states."""
    base = {
        ("rev-parse", "--is-inside-work-tree"): (0, "true", ""),
        ("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"): (0, "origin/main", ""),
        ("fetch", "--quiet"): (0, "", ""),
        ("rev-parse", "--short", "HEAD"): (0, "abc1234", ""),
        ("log", "-1", "--pretty=%s"): (0, "local subject", ""),
        ("rev-parse", "--short", "origin/main"): (0, "def5678", ""),
        ("rev-list", "--count", "HEAD..origin/main"): (0, "0", ""),
        ("rev-list", "--count", "origin/main..HEAD"): (0, "0", ""),
        ("status", "--porcelain"): (0, "", ""),
        ("log", "--pretty=%s", "HEAD..origin/main"): (0, "", ""),
        ("diff", "--name-only", "HEAD..origin/main"): (0, "", ""),
        ("pull", "--ff-only"): (0, "Updating abc1234..def5678", ""),
    }
    if overrides:
        base.update(overrides)

    def fake(*args, timeout=30):
        return base.get(tuple(args), (0, "", ""))

    return fake


def test_up_to_date(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder())
    status = updater.check_for_updates()
    assert status.checked and status.error is None
    assert not status.available and status.behind == 0


def test_updates_available_flags(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-list", "--count", "HEAD..origin/main"): (0, "3", ""),
        ("log", "--pretty=%s", "HEAD..origin/main"): (0, "feat: a\nfix: b\nchore: c", ""),
        ("diff", "--name-only", "HEAD..origin/main"): (0, "main.py\nrequirements.txt\ndesktop/src-tauri/src/main.rs", ""),
    }))
    status = updater.check_for_updates()
    assert status.available and status.behind == 3
    assert status.changelog == ["feat: a", "fix: b", "chore: c"]
    assert status.deps_changed and status.shell_changed


def test_dirty_tree(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-list", "--count", "HEAD..origin/main"): (0, "2", ""),
        ("status", "--porcelain"): (0, " M main.py", ""),
    }))
    status = updater.check_for_updates()
    assert status.available and status.dirty


def test_not_a_git_repo(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-parse", "--is-inside-work-tree"): (1, "", "fatal: not a git repository"),
    }))
    status = updater.check_for_updates()
    assert status.error and not status.available


def test_no_upstream(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"): (1, "", "no upstream"),
    }))
    status = updater.check_for_updates()
    assert status.error and "upstream" in status.error.lower()


def test_apply_refuses_dirty(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-list", "--count", "HEAD..origin/main"): (0, "1", ""),
        ("status", "--porcelain"): (0, " M x", ""),
    }))
    result = updater.apply_update()
    assert not result["ok"] and "local" in result["message"].lower()


def test_apply_refuses_local_ahead(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-list", "--count", "HEAD..origin/main"): (0, "1", ""),
        ("rev-list", "--count", "origin/main..HEAD"): (0, "2", ""),
    }))
    result = updater.apply_update()
    assert not result["ok"] and "local commit" in result["message"].lower()


def test_apply_success_reports_deps(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder({
        ("rev-list", "--count", "HEAD..origin/main"): (0, "1", ""),
        ("diff", "--name-only", "HEAD..origin/main"): (0, "requirements.txt", ""),
    }))
    result = updater.apply_update()
    assert result["ok"] and result.get("deps_changed") is True


def test_apply_noop_when_current(monkeypatch):
    monkeypatch.setattr(updater, "_git", _responder())
    result = updater.apply_update()
    assert result["ok"] and result.get("no_op")
