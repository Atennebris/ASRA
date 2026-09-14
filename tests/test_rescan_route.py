"""POST /api/session/{id}/rescan: re-audits an already-completed project as a brand-new session,
with its findings passed to the new one to actively re-verify (agent/core.py's _run_reverify)
rather than trust forward. The old session must never be mutated by this route.

Both /rescan and /rescan-in-place follow the same create->review->start split as start_scan's own
"Create" (see tests/test_create_start_split.py): they only ever prepare a session (status=
"created"), never schedule a run themselves -- a real, explicitly requested fix, since both used
to background_tasks.add_task the run in the same request that prepared it.
"""
from datetime import datetime, timezone

from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.tools import allowed_targets, native
from agent.tools.allowed_targets import is_target_allowed
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    monkeypatch.setattr(main, "_CREDENTIALS_DIR", tmp_path / "credentials")
    monkeypatch.setattr(main, "run_session", _fake_run_session)


def test_rescan_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/session/usr_does_not_exist/rescan")
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_works_for_an_interrupted_session_not_just_a_completed_one(tmp_path, monkeypatch):
    """Real, explicitly requested behavior: Rescan must not require the old run to have finished --
    an interrupted/failed session's real, already-durable findings are just as valid a baseline for
    _run_reverify to re-check. Resume alone doesn't cover "start an independent re-audit"."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = create_session("example.com", name="Interrupted project")
        session = load_session(session_id)
        session["status"] = "interrupted"
        session["findings"] = [{
            "title": "Partial finding", "severity": "Medium", "description": "d", "technology": "PHP",
            "exploitation_scenario": "remote_direct", "qualifies_for_bounty": "qualifying",
            "reproduction_steps": "steps", "evidence_ref": "partial evidence",
            "found_at": "2026-01-01T00:00:00+00:00", "verification": "verified",
        }]
        store.save_session(session_id, session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/rescan", follow_redirects=False)
        assert resp.status_code == 303

        new_id = resp.headers["location"].rstrip("/").split("/")[-1]
        new_session = load_session(new_id)
        assert new_session["carried_over_findings"][0]["title"] == "Partial finding"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_works_for_a_still_processing_session(tmp_path, monkeypatch):
    """The old session is only ever read (a frozen snapshot at rescan time), never mutated -- safe
    to allow even while it's actively running."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = create_session("example.com", name="Live project")
        session = load_session(session_id)
        session["status"] = "processing"
        store.save_session(session_id, session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/rescan", follow_redirects=False)
        assert resp.status_code == 303

        # The old session itself is untouched -- still "processing", not silently altered.
        assert load_session(session_id)["status"] == "processing"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def _make_completed_session(name="Old project", target="example.com", **extra):
    session_id = create_session(target, name=name, **extra)
    session = load_session(session_id)
    session["status"] = "completed"
    # A genuinely completed session always has this set (run_session's own doing) -- continue_deeper_session
    # now gates on it (see main.py), so a fixture claiming "completed" without it doesn't match real state.
    session["started_at"] = datetime.now(timezone.utc).isoformat()
    session["findings"] = [
        {
            "title": "Old XSS", "severity": "High", "description": "d", "technology": "PHP",
            "exploitation_scenario": "remote_direct", "qualifies_for_bounty": "qualifying",
            "reproduction_steps": "steps", "evidence_ref": "old evidence",
            "found_at": "2026-01-01T00:00:00+00:00", "verification": "verified",
        }
    ]
    store.save_session(session_id, session)
    return session_id


def test_rescan_creates_a_new_session_linked_back_to_the_old_one(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)

        assert resp.status_code == 303, resp.text
        new_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert new_id != old_id

        new_session = load_session(new_id)
        assert new_session["rescanned_from"] == old_id
        assert new_session["rescanned_from_name"] == "Old project"
        assert new_session["rescanned_from_target"] == "example.com"
        assert new_session["target"] == "example.com"
        # Create-only -- the operator must get a chance to review before it actually runs.
        assert new_session["status"] == "created"

        old_session = load_session(old_id)
        # The old session must never be mutated by this route.
        assert "rescanned_from" not in old_session
        assert old_session["status"] == "completed"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_does_not_schedule_a_background_run(tmp_path, monkeypatch):
    """Real regression this guards: /rescan used to background_tasks.add_task the new session's
    run in the same request that created it -- no review step at all, unlike start_scan's own
    Create/Start split."""
    from unittest.mock import MagicMock
    _isolate(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(main, "run_session", MagicMock())
        old_id = _make_completed_session()
        client = TestClient(main.app)
        client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        main.run_session.assert_not_called()
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_carries_over_the_old_sessions_llm_provider(tmp_path, monkeypatch):
    """Previously silently dropped -- the new session fell back to create_session's own default
    provider instead of the operator's actual persisted choice."""
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session(llm_provider="qwen")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(new_id)["llm_provider"] == "qwen"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_can_then_be_started_via_the_start_route(tmp_path, monkeypatch):
    """The deliberate second step -- same route a fresh "Create" project uses."""
    from unittest.mock import AsyncMock
    _isolate(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(main, "run_session", AsyncMock())
        old_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        start_resp = client.post(f"/api/session/{new_id}/start", follow_redirects=False)
        assert start_resp.status_code == 303
        assert load_session(new_id)["status"] == "pending"
        main.run_session.assert_called_once_with(new_id, provider_id=None, entry_point="recon")
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_carries_over_the_old_findings_as_a_frozen_snapshot(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_session = load_session(new_id)
        assert len(new_session["carried_over_findings"]) == 1
        assert new_session["carried_over_findings"][0]["title"] == "Old XSS"
        assert new_session["findings"] == []  # not pre-populated -- _run_reverify does that live
        assert new_session["reverification_history"] == []
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_carries_over_chain_attempts(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        old_session = load_session(old_id)
        old_session["chain_attempts"] = [{
            "ran_at": "2026-01-01T00:00:00+00:00", "hop": 1, "outcome": "chain_found",
            "finding_titles": ["Old XSS"], "reasoning": "cookie theft -> session hijack",
        }]
        store.save_session(old_id, old_session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_session = load_session(new_id)
        assert new_session["chain_attempts"] == old_session["chain_attempts"]
        # deepcopy independence -- mutating the new session's copy must never touch the old one
        new_session["chain_attempts"][0]["outcome"] = "mutated"
        assert load_session(old_id)["chain_attempts"][0]["outcome"] == "chain_found"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_carries_over_map_manual(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        old_session = load_session(old_id)
        old_session["map_manual"] = {
            "nodes": [{"id": "n1", "label": "Internal admin panel", "kind": "note", "notes": ""}],
            "edges": [], "positions": {"n1": {"x": 10, "y": 20}},
        }
        store.save_session(old_id, old_session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_session = load_session(new_id)
        assert new_session["map_manual"] == old_session["map_manual"]
        new_session["map_manual"]["nodes"][0]["label"] = "mutated"
        assert load_session(old_id)["map_manual"]["nodes"][0]["label"] == "Internal admin panel"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_carries_over_the_old_sessions_hypotheses(tmp_path, monkeypatch):
    """Real, confirmed gap this fixes: a brand-new /rescan used to silently drop every hypothesis
    (open, confirmed, or ruled_out) from the prior scan -- unlike findings/recon, nothing was ever
    read from old_session["hypotheses"] at all."""
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        old_session = load_session(old_id)
        old_session["hypotheses"] = [
            {"id": "h1", "text": "Admin panel may be reachable unauthenticated", "evidence": "e",
             "status": "ruled_out", "resolution_note": "requires auth", "source_phase": "recon",
             "source": "agent", "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": "2026-01-01T00:05:00+00:00"},
        ]
        store.save_session(old_id, old_session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_session = load_session(new_id)
        assert new_session["hypotheses"] == old_session["hypotheses"]
        new_session["hypotheses"][0]["status"] = "mutated"
        assert load_session(old_id)["hypotheses"][0]["status"] == "ruled_out"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_carries_over_past_hypothesis_outcomes(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        old_session = load_session(old_id)
        old_session["past_hypothesis_outcomes"] = [
            {"text": "Admin panel may be reachable unauthenticated", "status": "ruled_out",
             "resolution_note": "requires auth", "resolved_at": "2026-01-01T00:05:00+00:00"},
        ]
        store.save_session(old_id, old_session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_session = load_session(new_id)
        assert new_session["past_hypothesis_outcomes"] == old_session["past_hypothesis_outcomes"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_resets_host_health_streaks_so_a_new_pass_is_never_pre_blocked(tmp_path, monkeypatch):
    """A host blocked "dead" at the very end of the prior pass must not start the new rescan already
    blocked with zero real attempt made in it -- see sessions/store.py's
    reset_host_health_streaks_for_new_pass."""
    from agent.core import _dead_host_blocked

    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        old_session = load_session(old_id)
        old_session["recon_result"] = {
            "targets": [], "host_health": {
                "example.com": {
                    "failures": 5, "successes": 0, "consecutive_failures": 5, "last_error": "timeout",
                    "consecutive_failure_tools": ["nmap", "whatweb"],
                },
            },
        }
        store.save_session(old_id, old_session)
        # Confirm the fixture is actually at the blocking threshold before rescanning.
        assert _dead_host_blocked(old_session, {"target": "example.com"}) is not None

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_session = load_session(new_id)
        entry = new_session["recon_result"]["host_health"]["example.com"]
        assert entry["consecutive_failures"] == 0
        assert entry["consecutive_failure_tools"] == []
        assert entry["failures"] == 5  # lifetime totals preserved, not wiped
        assert _dead_host_blocked(new_session, {"target": "example.com"}) is None
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_copies_credentials_file_when_the_old_session_has_one(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        native._CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
        (native._CREDENTIALS_DIR / f"{old_id}.json").write_text('{"user_a": {"cookie": "sessionid=abc"}}', encoding="utf-8")

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]

        new_credentials_path = native._CREDENTIALS_DIR / f"{new_id}.json"
        assert new_credentials_path.exists()
        assert "sessionid=abc" in new_credentials_path.read_text(encoding="utf-8")
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_is_harmless_when_the_old_session_has_no_credentials_file(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        assert resp.status_code == 303
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_replays_exploit_authorization_when_old_session_had_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session(target="example.com", enumerate_subdomains=True, authorize_exploit=True)
        client = TestClient(main.app)
        client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)

        # The wildcard-on-checkbox fix from earlier this session: enumerate_subdomains=True means
        # the whole subdomain tree gets authorized, not just the literal typed host.
        assert is_target_allowed("forum.example.com") is True
        assert is_target_allowed("example.com") is True
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_does_not_authorize_exploitation_when_old_session_never_had_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session(target="never-authorized.example")
        client = TestClient(main.app)
        client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)

        assert is_target_allowed("never-authorized.example") is False
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_does_not_authorize_for_a_pre_existing_session_missing_the_field(tmp_path, monkeypatch):
    """An old session saved before authorize_exploit existed on the schema (.get returns None) must
    not be treated as authorized -- an honest, conservative limitation, not a guess that could
    over-authorize a target the user never actually intended to authorize."""
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session(target="legacy-session.example")
        old_session = load_session(old_id)
        del old_session["authorize_exploit"]
        store.save_session(old_id, old_session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        assert resp.status_code == 303

        assert is_target_allowed("legacy-session.example") is False
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


# --- rescan naming: numbered, not a fixed duplicate-prone suffix -------------------------------


def test_rescan_names_the_new_project_rescan_1_the_first_time(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(new_id)["name"] == "Old project - Rescan 1"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_numbers_up_instead_of_producing_a_duplicate_name(tmp_path, monkeypatch):
    """Real gap this closes: the old fixed "(rescan)" suffix gave every rescan of the same project
    the identical display name, impossible to tell apart in the Projects list once there was more
    than one."""
    _isolate(tmp_path, monkeypatch)
    try:
        old_id = _make_completed_session()
        client = TestClient(main.app)

        resp1 = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id_1 = resp1.headers["location"].rsplit("/", 1)[-1]
        assert load_session(new_id_1)["name"] == "Old project - Rescan 1"

        resp2 = client.post(f"/api/session/{old_id}/rescan", follow_redirects=False)
        new_id_2 = resp2.headers["location"].rsplit("/", 1)[-1]
        assert load_session(new_id_2)["name"] == "Old project - Rescan 2"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_next_rescan_name_strips_an_existing_suffix_before_numbering(tmp_path, monkeypatch):
    """Rescanning an already-numbered rescan must not compound into "X - Rescan 1 - Rescan 2" -- the
    root name is recovered by stripping the existing suffix first, so with no other rescans of that
    same root on record yet, numbering restarts at 1 off the TRUE root name."""
    _isolate(tmp_path, monkeypatch)
    try:
        assert main._next_rescan_name("Old project - Rescan 5") == "Old project - Rescan 1"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_next_rescan_name_of_a_rescan_continues_numbering_off_existing_siblings(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        create_session("example.com", name="Old project - Rescan 1")
        create_session("example.com", name="Old project - Rescan 2")
        # Rescanning the "- Rescan 2" project itself must still number off the shared root, landing
        # on 3 -- not treat "Old project - Rescan 2" as its own separate root starting back at 1.
        assert main._next_rescan_name("Old project - Rescan 2") == "Old project - Rescan 3"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


# --- rescan-in-place: re-audits the SAME session, never creates a new one -----------------------


def test_rescan_in_place_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/session/usr_does_not_exist/rescan-in-place")
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_in_place_rejects_a_currently_running_session(tmp_path, monkeypatch):
    """Unlike /rescan (always an independent new session, nothing to race), this mutates the SAME
    session file a live run_session() loop could be mid-write on -- must never fire while one is
    actually in flight."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        session = load_session(session_id)
        session["status"] = "processing"
        store.save_session(session_id, session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/rescan-in-place")
        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_in_place_moves_findings_into_carried_over_findings(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/rescan-in-place", follow_redirects=False)
        assert resp.status_code == 303

        # Same session_id — never a new project.
        assert resp.headers["location"].rstrip("/").rsplit("/", 1)[-1] == session_id

        session = load_session(session_id)
        # Real operator complaint this fixes: the Findings tab used to crater to 0 the instant a
        # rescan started and only climb back up as _run_reverify worked through carried_over_
        # findings (which can take many minutes) — session["findings"] is now seeded with a copy
        # of the same findings, each tagged _carried_over_pending_reverify, instead of left empty.
        assert len(session["findings"]) == 1
        assert session["findings"][0]["title"] == "Old XSS"
        assert session["findings"][0]["_carried_over_pending_reverify"] is True
        assert len(session["carried_over_findings"]) == 1
        assert session["carried_over_findings"][0]["title"] == "Old XSS"
        # The seeded placeholder must never itself carry the marker back onto carried_over_findings
        # (that list is the frozen, untagged snapshot _run_reverify reads from).
        assert "_carried_over_pending_reverify" not in session["carried_over_findings"][0]
        assert session["reverification_history"] == []
        assert session["in_place_rescan_count"] == 1
        assert session["last_rescanned_at"]
        # Create-only -- the operator must get a chance to review before it actually runs.
        assert session["status"] == "created"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_in_place_does_not_schedule_a_background_run(tmp_path, monkeypatch):
    """Real regression this guards: /rescan-in-place used to background_tasks.add_task the pass in
    the same request that prepared it -- no review step at all."""
    from unittest.mock import MagicMock
    _isolate(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(main, "run_session", MagicMock())
        session_id = _make_completed_session()
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/rescan-in-place", follow_redirects=False)
        main.run_session.assert_not_called()
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_in_place_can_then_be_started_via_the_start_route(tmp_path, monkeypatch):
    """The deliberate second step -- same route a fresh "Create" project uses."""
    from unittest.mock import AsyncMock
    _isolate(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(main, "run_session", AsyncMock())
        session_id = _make_completed_session()
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/rescan-in-place", follow_redirects=False)

        start_resp = client.post(f"/api/session/{session_id}/start", follow_redirects=False)
        assert start_resp.status_code == 303
        assert load_session(session_id)["status"] == "pending"
        main.run_session.assert_called_once_with(session_id, provider_id=None, entry_point="recon")
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_in_place_leaves_hypotheses_and_targets_untouched(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        session = load_session(session_id)
        session["hypotheses"] = [{"id": "h1", "text": "a lead", "status": "unconfirmed"}]
        session["recon_result"] = {"targets": [{"host": "example.com", "port": 443}], "cves": []}
        store.save_session(session_id, session)

        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/rescan-in-place", follow_redirects=False)

        reloaded = load_session(session_id)
        assert reloaded["hypotheses"] == session["hypotheses"]
        assert reloaded["recon_result"]["targets"] == session["recon_result"]["targets"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_in_place_increments_the_pass_count_across_repeated_calls(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        client = TestClient(main.app)

        client.post(f"/api/session/{session_id}/rescan-in-place", follow_redirects=False)
        # Lands on status="created" (create-only, not run) -- not in _ORPHANABLE_STATUSES, so a
        # second call back-to-back would already succeed on its own; this still exercises the more
        # realistic path where the operator actually started and finished the first pass first.
        session = load_session(session_id)
        session["status"] = "completed"
        store.save_session(session_id, session)

        client.post(f"/api/session/{session_id}/rescan-in-place", follow_redirects=False)

        assert load_session(session_id)["in_place_rescan_count"] == 2
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


# --- continue-deeper: one-click in-place pass with an escalation-shaped default goal -----------


def test_continue_deeper_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/session/usr_does_not_exist/continue-deeper")
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_rejects_a_currently_running_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        session = load_session(session_id)
        session["status"] = "processing"
        store.save_session(session_id, session)

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/continue-deeper")
        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_rejects_a_session_that_has_never_been_started(tmp_path, monkeypatch):
    """A freshly created project (create_session's own default: status="created", no started_at
    yet) has no findings/recon/hypotheses of its own for an in-place pass to "dig deeper" into --
    the Overview tab's button itself is now gated on session.started_at (session_fragment.html),
    this is the server-side twin of that same guard so a direct POST can't bypass it either."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = create_session("example.com", name="Never started")
        assert load_session(session_id).get("started_at") is None

        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/continue-deeper")
        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_prepares_the_same_in_place_pass_as_rescan_in_place(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/continue-deeper", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"].rstrip("/").rsplit("/", 1)[-1] == session_id  # same session

        session = load_session(session_id)
        assert len(session["carried_over_findings"]) == 1
        assert session["carried_over_findings"][0]["title"] == "Old XSS"
        assert session["findings"][0]["_carried_over_pending_reverify"] is True
        assert session["reverification_history"] == []
        assert session["in_place_rescan_count"] == 1
        assert session["status"] == "created"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_defaults_the_goal_to_an_escalation_directive_when_none_is_set(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session()
        assert not load_session(session_id).get("goal")
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/continue-deeper", follow_redirects=False)
        assert load_session(session_id)["goal"] == main._DEFAULT_CONTINUE_DEEPER_GOAL
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_leaves_an_existing_goal_untouched(tmp_path, monkeypatch):
    """The operator's own real intent must not be silently overwritten by the generic default just
    because this is the one-click route rather than the dialog's own editable goal field."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session(goal="reach the admin panel")
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/continue-deeper", follow_redirects=False)
        assert load_session(session_id)["goal"] == "reach the admin panel"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_leaves_time_budget_seconds_untouched(tmp_path, monkeypatch):
    """No dialog to change it from -- unlike /rescan-in-place's own explicit preset/custom fields."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _make_completed_session(time_budget_seconds=3600)
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/continue-deeper", follow_redirects=False)
        assert load_session(session_id)["time_budget_seconds"] == 3600
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_continue_deeper_can_then_be_started_via_the_start_route(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock
    _isolate(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(main, "run_session", AsyncMock())
        session_id = _make_completed_session()
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/continue-deeper", follow_redirects=False)

        start_resp = client.post(f"/api/session/{session_id}/start", follow_redirects=False)
        assert start_resp.status_code == 303
        assert load_session(session_id)["status"] == "pending"
        main.run_session.assert_called_once_with(session_id, provider_id=None, entry_point="recon")
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
