"""RE mode's own Summary tab (templates/partials/re_summary_tab.html, wired into session.html's
re-info-tabbar as a 4th Graph/Logs/Findings/Summary tab) -- the RE-mode analog of the Agent
pipeline's Summary tab: process efficiency, findings-by-severity/verification breakdown, a
Hypotheses summary, and Target Profile, WITHOUT the bug-bounty-specific "Bounty scope match" /
"Qualifying findings" spotlight the Agent Summary tab has (RE mode has no scope_rules concept).
"""
from fastapi.testclient import TestClient

import main
import projects.paths as project_paths
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()


def _make_re_session(tmp_path, monkeypatch, **overrides) -> str:
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session(target="/path/to/binary", name="re-summary-test", mode="reverse_engineering")
    session = store.load_session(session_id)
    session.update(overrides)
    store.save_session(session_id, session)
    return session_id


def test_re_session_page_renders_summary_tab_with_no_data_yet(tmp_path, monkeypatch):
    session_id = _make_re_session(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert 'id="re-info-summary"' in resp.text
    assert ">Summary<" in resp.text
    assert "re-info-panel-summary" in resp.text
    # No crash and a sane empty state -- 0 findings, no target facts recorded yet.
    assert "No target facts yet" in resp.text


def test_re_session_summary_tab_shows_findings_and_hypotheses_breakdown(tmp_path, monkeypatch):
    session_id = _make_re_session(
        tmp_path, monkeypatch,
        status="completed",
        findings=[
            {"title": "Debug backdoor", "severity": "High", "verification": "verified"},
            {"title": "Weak hash", "severity": "Medium", "verification": "needs_verification"},
        ],
        hypotheses=[
            {"id": "h1", "text": "serial uses a hash", "status": "confirmed"},
            {"id": "h2", "text": "maybe XOR cipher", "status": "ruled_out"},
        ],
        target_profile=[{"label": "Language", "value": "Go"}, {"label": "Obfuscator", "value": "garble"}],
    )
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    body = resp.text
    assert "2 findings recorded against" in body
    assert "Debug backdoor" not in body.split('id="re-info-panel-summary"')[0]  # sanity: not just anywhere on the page
    assert "Language" in body and "Go" in body
    assert "garble" in body
    # Bug-bounty-only concepts must NOT appear in the RE Summary tab.
    assert "Bounty scope match" not in body
    assert "Qualifying findings" not in body
    # Export is offered (status == completed and findings exist).
    assert f'/api/session/{session_id}/export' in body


def test_re_session_summary_tab_omits_export_when_not_completed(tmp_path, monkeypatch):
    session_id = _make_re_session(
        tmp_path, monkeypatch,
        status="interrupted",
        findings=[{"title": "Something", "severity": "Low", "verification": "inferred"}],
    )
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert f'/api/session/{session_id}/export' not in resp.text
