"""Debug module: resolve_global_app_dir() (projects/paths.py), the exclusive-routing behavior
(a record with no active session lands in the global app log; a record WITH an active
current_session_id lands only in that session's own project folder, never both --
agent/utils/debug.py), and the client-event HTTP endpoint main.py exposes for the browser side
(static/js/debug_events.js).
"""
import logging

import agent.utils.debug as debug_mod
import projects.paths as paths_mod


def test_resolve_global_app_dir_defaults_to_documents_asra(tmp_path, monkeypatch):
    paths_mod.resolve_global_app_dir.cache_clear()
    monkeypatch.delenv("APP_DATA_DIR", raising=False)
    monkeypatch.setattr(paths_mod, "_resolve_documents_dir", lambda: tmp_path)

    result = paths_mod.resolve_global_app_dir()

    assert result == tmp_path / "ASRA"
    paths_mod.resolve_global_app_dir.cache_clear()


def test_resolve_global_app_dir_honors_override(tmp_path, monkeypatch):
    paths_mod.resolve_global_app_dir.cache_clear()
    override = tmp_path / "custom-asra-data"
    monkeypatch.setenv("APP_DATA_DIR", str(override))

    result = paths_mod.resolve_global_app_dir()

    assert result == override
    paths_mod.resolve_global_app_dir.cache_clear()
    monkeypatch.delenv("APP_DATA_DIR", raising=False)


def test_resolve_global_app_dir_is_a_sibling_of_projects_dir_not_nested_in_it(tmp_path, monkeypatch):
    paths_mod.resolve_global_app_dir.cache_clear()
    paths_mod.resolve_projects_base_dir.cache_clear()
    monkeypatch.delenv("APP_DATA_DIR", raising=False)
    monkeypatch.delenv("PROJECTS_DIR", raising=False)
    monkeypatch.setattr(paths_mod, "_resolve_documents_dir", lambda: tmp_path)

    app_dir = paths_mod.resolve_global_app_dir()
    projects_dir = paths_mod.resolve_projects_base_dir()

    assert app_dir.parent == projects_dir.parent
    assert app_dir != projects_dir
    paths_mod.resolve_global_app_dir.cache_clear()
    paths_mod.resolve_projects_base_dir.cache_clear()


def _make_record(logger_name="asra.TOOLS", message="hello"):
    return logging.LogRecord(logger_name, logging.DEBUG, __file__, 1, message, None, None)


def test_session_aware_handler_always_writes_the_global_file(tmp_path, monkeypatch):
    monkeypatch.setattr(debug_mod, "_session_folder", lambda: None)
    log_path = tmp_path / "debug.log"
    handler = debug_mod._SessionAwareFileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_make_record(message="no session active"))
    handler.close()

    assert "no session active" in log_path.read_text(encoding="utf-8")


def test_session_aware_handler_writes_only_the_session_folder_when_active(tmp_path, monkeypatch):
    """Real incident this guards against: before this exclusive routing existed, every
    session-scoped line ALSO landed in the global file unconditionally, so Documents/ASRA/debug.log
    grew to 249MB/256k lines across normal use -- a full duplicate copy of every project's own
    debug.log, forever. A record with an active session must land ONLY in that session's own
    project folder, never the global file too."""
    session_folder = tmp_path / "some-project-usr_x"
    monkeypatch.setattr(debug_mod, "_session_folder", lambda: session_folder)
    global_path = tmp_path / "global-debug.log"
    handler = debug_mod._SessionAwareFileHandler(global_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_make_record(message="scoped to this session"))
    handler.close()

    # logging.FileHandler.__init__ opens (creates) its file immediately regardless of whether
    # anything is ever emitted, so checking existence alone would be a false pass either way --
    # what actually matters is that this session-scoped record's own content never reached it.
    assert "scoped to this session" not in global_path.read_text(encoding="utf-8")
    assert "scoped to this session" in (session_folder / "debug.log").read_text(encoding="utf-8")


def test_session_folder_reads_the_context_var_and_resolves_via_get_session_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(debug_mod, "current_session_id", debug_mod.contextvars.ContextVar("t", default=None))
    token = debug_mod.current_session_id.set("usr_abc")

    import sessions.store as store_mod
    monkeypatch.setattr(store_mod, "get_session_folder", lambda sid: str(tmp_path / sid) if sid == "usr_abc" else None)
    # native _session_folder does a local import of sessions.store -- patch the real module so
    # that lazy import sees the patched function.
    monkeypatch.setattr("sessions.store.get_session_folder", store_mod.get_session_folder)

    result = debug_mod._session_folder()

    debug_mod.current_session_id.reset(token)
    assert result == tmp_path / "usr_abc"


def test_session_folder_is_none_with_no_active_session():
    assert debug_mod.current_session_id.get() is None
    assert debug_mod._session_folder() is None


def test_dump_large_payload_goes_into_the_session_folder_when_active(tmp_path, monkeypatch):
    session_folder = tmp_path / "proj"
    monkeypatch.setattr(debug_mod, "_session_folder", lambda: session_folder)

    path_str = debug_mod.dump_large_payload("step_1", "a" * 1000)

    assert (session_folder / "debug-tool-calls" / "step_1.txt").exists()
    assert path_str.endswith("step_1.txt")


def test_dump_large_payload_falls_back_to_global_dir_with_no_active_session(tmp_path, monkeypatch):
    monkeypatch.setattr(debug_mod, "_session_folder", lambda: None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)

    debug_mod.dump_large_payload("step_2", "b" * 1000)

    assert (tmp_path / "debug-tool-calls" / "step_2.txt").exists()


def test_truncate_for_log_leaves_short_content_untouched():
    assert debug_mod.truncate_for_log("short") == "short"


def test_file_handler_format_includes_the_local_utc_offset(tmp_path):
    """Real near-mistake this covers: debug.log uses the machine's own local clock (deliberately --
    see this module's own docstring) while session.json's own timestamps are all UTC. Cross-
    referencing the two without knowing which is which produces a silently wrong elapsed time --
    confirmed live during a real session review, a debug.log timestamp read against a session.json
    UTC timestamp looked like a 4.5-hour session that was actually 1.5 hours. Every debug.log line
    must carry its own explicit offset so it's self-describing wherever it ends up read."""
    handler = debug_mod.build_file_handler()
    formatted = handler.format(_make_record(message="hello"))
    handler.close()
    assert debug_mod._LOCAL_UTC_OFFSET in formatted
    # A real offset looks like +0300/-0500, not the "no local timezone info" fallback.
    assert len(debug_mod._LOCAL_UTC_OFFSET) == 5
    assert debug_mod._LOCAL_UTC_OFFSET[0] in "+-"


def test_console_formatter_includes_the_local_utc_offset():
    formatter = debug_mod._CategoryConsoleFormatter("TOOLS")
    formatted = formatter.format(_make_record(message="hello"))
    assert debug_mod._LOCAL_UTC_OFFSET in formatted


def test_session_aware_handler_updates_the_active_session_pointer_file(tmp_path, monkeypatch):
    """Real incident this fixes: run.bat's separate debug console window only ever tails the
    GLOBAL log (by design -- session-scoped lines deliberately never land there), so an operator
    watching it during a real, active scan saw almost nothing and reasonably read that as the
    console being broken. The pointer file lets that window additionally find and tail whichever
    project log is actually active, without changing where anything is actually stored."""
    monkeypatch.setattr(debug_mod, "_last_pointer_target", None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)
    session_folder = tmp_path / "some-project-usr_x"
    monkeypatch.setattr(debug_mod, "_session_folder", lambda: session_folder)
    global_path = tmp_path / "global-debug.log"
    handler = debug_mod._SessionAwareFileHandler(global_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_make_record(message="scoped to this session"))
    handler.close()

    pointer_path = tmp_path / debug_mod._ACTIVE_SESSION_LOG_POINTER_NAME
    assert pointer_path.read_text(encoding="utf-8") == str(session_folder / "debug.log")


def test_session_aware_handler_leaves_the_pointer_file_untouched_with_no_active_session(tmp_path, monkeypatch):
    monkeypatch.setattr(debug_mod, "_last_pointer_target", None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setattr(debug_mod, "_session_folder", lambda: None)
    global_path = tmp_path / "global-debug.log"
    handler = debug_mod._SessionAwareFileHandler(global_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_make_record(message="no session active"))
    handler.close()

    assert not (tmp_path / debug_mod._ACTIVE_SESSION_LOG_POINTER_NAME).exists()


def test_update_active_session_log_pointer_skips_the_write_when_target_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(debug_mod, "_last_pointer_target", None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)
    target = tmp_path / "proj" / "debug.log"

    debug_mod._update_active_session_log_pointer(target)
    pointer_path = tmp_path / debug_mod._ACTIVE_SESSION_LOG_POINTER_NAME
    first_write_time = pointer_path.stat().st_mtime_ns

    debug_mod._update_active_session_log_pointer(target)  # same target again

    assert pointer_path.stat().st_mtime_ns == first_write_time


def test_update_active_session_log_pointer_switches_when_the_active_project_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(debug_mod, "_last_pointer_target", None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)

    debug_mod._update_active_session_log_pointer(tmp_path / "proj-a" / "debug.log")
    debug_mod._update_active_session_log_pointer(tmp_path / "proj-b" / "debug.log")

    pointer_path = tmp_path / debug_mod._ACTIVE_SESSION_LOG_POINTER_NAME
    assert pointer_path.read_text(encoding="utf-8") == str(tmp_path / "proj-b" / "debug.log")


def test_to_windows_path_if_wsl_mount_converts_a_wsl_drive_mount_path():
    # scripts/debug_console.ps1 is a genuine native Win32 PowerShell process (no WSL hop --
    # see that script's own docstring), so a bare /mnt/c/... string silently Test-Path's to
    # "doesn't exist" there even though the real file is right there on the C: drive.
    assert (
        debug_mod._to_windows_path_if_wsl_mount("/mnt/c/Users/user/Documents/ASRA Projects/proj/debug.log")
        == r"C:\Users\user\Documents\ASRA Projects\proj\debug.log"
    )


def test_to_windows_path_if_wsl_mount_leaves_a_native_path_untouched():
    # Native Linux/macOS (run.sh, no WSL involved at all) never produces this shape for its own
    # app-data dir -- scripts/debug_console.py reads this same pointer file there expecting an
    # ordinary native path, so a real one must pass through byte-for-byte unchanged.
    native_path = "/home/user/Documents/ASRA Projects/proj/debug.log"
    assert debug_mod._to_windows_path_if_wsl_mount(native_path) == native_path


def test_update_active_session_log_pointer_writes_a_windows_path_for_a_wsl_mount_target(tmp_path, monkeypatch):
    monkeypatch.setattr(debug_mod, "_last_pointer_target", None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)

    debug_mod._update_active_session_log_pointer(
        debug_mod.Path("/mnt/c/Users/user/Documents/ASRA Projects/proj/debug.log")
    )

    pointer_path = tmp_path / debug_mod._ACTIVE_SESSION_LOG_POINTER_NAME
    assert pointer_path.read_text(encoding="utf-8") == r"C:\Users\user\Documents\ASRA Projects\proj\debug.log"


def test_client_event_endpoint_logs_ui_category(monkeypatch, tmp_path):
    import main

    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setattr(debug_mod, "is_debug_enabled", lambda: True)
    logging.getLogger("asra.UI").handlers.clear()
    import agent.utils.logger as logger_mod
    logger_mod._configured.discard("UI")

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    resp = client.post("/api/debug/client-event", json={"session_id": None, "action": "click", "detail": "#foo"})

    assert resp.status_code == 204
    log_content = (tmp_path / "debug.log").read_text(encoding="utf-8")
    assert "click: #foo" in log_content

    logging.getLogger("asra.UI").handlers.clear()
    logger_mod._configured.discard("UI")
