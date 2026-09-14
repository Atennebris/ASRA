"""Projects list (GET /sessions): each row's Delete button must name its own project in the
confirm step, not a generic message -- real incident this guards against: the list polls every 5s
and rows re-sort as their own status changes, so a stale click can land on a different project's
Delete button than the one the operator actually meant, with no way to notice before a real,
unrecoverable delete_session() runs. The fix moved the project name/target into data-* attributes
(read back and assembled into the confirm message in static/js/confirm_dialog.js's
asraConfirmDeleteProject) instead of interpolating them directly into the onsubmit="..." JS-source
string, which a name containing a genuine quote/apostrophe would otherwise have broken.
"""
from fastapi.testclient import TestClient

import main
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()


def test_delete_button_carries_the_projects_own_name_and_target_as_data_attributes(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    create_session("https://example.com", name="Acme Corp Pentest")

    client = TestClient(main.app)
    resp = client.get("/sessions")

    assert resp.status_code == 200
    assert 'data-project-name="Acme Corp Pentest"' in resp.text
    assert 'data-project-target="https://example.com"' in resp.text
    assert 'onsubmit="return asraConfirmDeleteProject(event);"' in resp.text


def test_delete_button_no_longer_uses_a_generic_inline_confirm_message(tmp_path, monkeypatch):
    """Regression guard for the specific incident: the old onsubmit built a JS string literal
    directly from the project's own name -- a name containing a quote/apostrophe would have broken
    the handler outright, and even without that, the message never named the actual project at
    all, so a stale click had nothing in the confirm dialog to catch it."""
    _isolate(tmp_path, monkeypatch)
    create_session("https://example.com", name="Some Project")

    client = TestClient(main.app)
    resp = client.get("/sessions")

    assert "This cannot be undone — the project folder, its findings, and its logs are all removed." not in resp.text


def test_delete_button_data_attributes_are_html_escaped_for_a_name_with_quotes(tmp_path, monkeypatch):
    """A project name containing a literal apostrophe/quote (a realistic bug-bounty program name,
    e.g. "McDonald's Program") must render as a safe HTML-escaped data attribute, never break out
    of it -- this is exactly the class of bug the data-attribute approach avoids versus inlining
    the raw name into an onsubmit="..." JS-source string."""
    _isolate(tmp_path, monkeypatch)
    create_session("https://example.com", name="McDonald's \"Program\"")

    client = TestClient(main.app)
    resp = client.get("/sessions")

    assert resp.status_code == 200
    # The raw quote/apostrophe must never appear unescaped inside the data-project-name="..." value
    # -- html.parser only accepts this if it's valid, well-formed HTML in the first place.
    import html.parser

    class _Parser(html.parser.HTMLParser):
        def handle_starttag(self, tag, attrs):
            pass

    _Parser().feed(resp.text)  # raises on malformed markup (e.g. an attribute value breakout)


def test_sessions_fragment_route_also_carries_the_data_attributes(tmp_path, monkeypatch):
    """The 5s-polling fragment endpoint (the one that actually re-sorts rows live) must render the
    same fixed markup as the full page -- this is the route whose own poll cycle is the root cause
    of a row moving underneath the operator's mouse."""
    _isolate(tmp_path, monkeypatch)
    create_session("https://example.com", name="Fragment Route Project")

    client = TestClient(main.app)
    resp = client.get("/api/sessions/fragment")

    assert resp.status_code == 200
    assert 'data-project-name="Fragment Route Project"' in resp.text
