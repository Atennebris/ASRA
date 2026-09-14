"""Out of scope: the New Project form's optional exclusion field (sessions/store.py's
create_session -> session["out_of_scope"]), the shared hostname-matching logic it reuses from the
exploitation allowlist (agent/tools/allowed_targets.py's is_target_out_of_scope), and the
deterministic per-call guard that actually enforces it (agent/core.py's _out_of_scope_target,
wired into _run_tool_with_retry) -- a real, code-level skip, not just a prompt suggestion the
model could ignore.
"""
import asyncio

from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.core import (
    RunContext,
    _out_of_scope_notes_task_addendum,
    _out_of_scope_target,
    _out_of_scope_task_addendum,
    _run_tool_with_retry,
)
from agent.tools.allowed_targets import is_target_out_of_scope
from agent.tools.registry import ToolSpec
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


def _run(coro):
    return asyncio.run(coro)


def test_create_session_defaults_out_of_scope_to_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = create_session("example.com")
        assert load_session(session_id)["out_of_scope"] == []
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_create_session_stores_out_of_scope_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = create_session("*.example.com", out_of_scope=["staging.example.com", "*.internal.example.com"])
        assert load_session(session_id)["out_of_scope"] == ["staging.example.com", "*.internal.example.com"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_is_target_out_of_scope_matches_an_exact_entry():
    assert is_target_out_of_scope("staging.example.com", ["staging.example.com"]) is True
    assert is_target_out_of_scope("https://staging.example.com/login", ["staging.example.com"]) is True


def test_is_target_out_of_scope_matches_a_wildcard_entry():
    assert is_target_out_of_scope("admin.internal.example.com", ["*.internal.example.com"]) is True
    assert is_target_out_of_scope("internal.example.com", ["*.internal.example.com"]) is True


def test_is_target_out_of_scope_false_for_an_unrelated_host():
    assert is_target_out_of_scope("app.example.com", ["staging.example.com"]) is False


def test_out_of_scope_target_returns_none_when_list_is_empty():
    assert _out_of_scope_target({"out_of_scope": []}, {"target": "staging.example.com"}) is None
    assert _out_of_scope_target({}, {"target": "staging.example.com"}) is None


def test_out_of_scope_target_matches_target_host_and_domain_arguments():
    session = {"out_of_scope": ["staging.example.com"]}
    assert _out_of_scope_target(session, {"target": "https://staging.example.com/x"}) == "https://staging.example.com/x"
    assert _out_of_scope_target(session, {"host": "staging.example.com"}) == "staging.example.com"
    assert _out_of_scope_target(session, {"domain": "staging.example.com"}) == "staging.example.com"
    assert _out_of_scope_target(session, {"target": "app.example.com"}) is None


def test_out_of_scope_task_addendum_is_empty_when_blank():
    assert _out_of_scope_task_addendum({"out_of_scope": []}) == ""
    assert _out_of_scope_task_addendum({}) == ""


def test_out_of_scope_task_addendum_lists_the_excluded_hosts():
    addendum = _out_of_scope_task_addendum({"out_of_scope": ["staging.example.com", "*.internal.example.com"]})
    assert "staging.example.com" in addendum
    assert "*.internal.example.com" in addendum


# --- out_of_scope_notes: free-text scope qualifiers that don't parse as a host/domain/URL ---


def test_create_session_defaults_out_of_scope_notes_to_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = create_session("example.com")
        assert load_session(session_id)["out_of_scope_notes"] == []
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_create_session_stores_out_of_scope_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = create_session(
            "*.example.com",
            out_of_scope=["staging.example.com"],
            out_of_scope_notes=["All domains or subdomains not listed in the above list of Scopes"],
        )
        session = load_session(session_id)
        assert session["out_of_scope"] == ["staging.example.com"]
        assert session["out_of_scope_notes"] == ["All domains or subdomains not listed in the above list of Scopes"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_out_of_scope_notes_task_addendum_is_empty_when_blank():
    assert _out_of_scope_notes_task_addendum({"out_of_scope_notes": []}) == ""
    assert _out_of_scope_notes_task_addendum({}) == ""


def test_out_of_scope_notes_task_addendum_includes_the_free_text_note():
    addendum = _out_of_scope_notes_task_addendum(
        {"out_of_scope_notes": ["All domains or subdomains not listed in the above list of Scopes"]}
    )
    assert "All domains or subdomains not listed in the above list of Scopes" in addendum


# --- /api/scan: a free-text out-of-scope phrase must not fail form validation the way a
# malformed target/allowlist host still correctly does ---


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def test_scan_form_accepts_a_free_text_out_of_scope_phrase(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan",
            data={
                "name": "Free Text OOS Project",
                "target": "example.com",
                "out_of_scope": "staging.example.com, All domains or subdomains not listed in the above list of Scopes",
            },
            follow_redirects=False,
        )

        assert resp.status_code == 303, resp.text
        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        session = load_session(session_id)
        assert session["out_of_scope"] == ["staging.example.com"]
        assert session["out_of_scope_notes"] == ["All domains or subdomains not listed in the above list of Scopes"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_scan_form_still_rejects_a_malformed_target(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan",
            data={"name": "Bad Target Project", "target": "not a valid target !!"},
            follow_redirects=False,
        )

        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def _make_tool(name: str = "http_request") -> ToolSpec:
    return ToolSpec(
        name=name, category="scan", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True,
        native_function=lambda args: {"status": "ok", "tool": name, "called_with": args},
    )


def test_run_tool_with_retry_skips_a_call_against_an_out_of_scope_target(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {"session_id": "usr_oos_test", "logs": [], "out_of_scope": ["staging.example.com"]}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = _make_tool()

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "https://staging.example.com/login"}))

    assert result["status"] == "skipped"
    assert "out of scope" in result["reason"]


def test_run_tool_with_retry_runs_normally_for_an_in_scope_target(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {"session_id": "usr_oos_clear", "logs": [], "out_of_scope": ["staging.example.com"]}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = _make_tool()

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "https://app.example.com/login"}))

    assert result["status"] == "ok"
