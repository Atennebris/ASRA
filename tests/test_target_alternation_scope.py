"""Pipe-alternation scope entries ("*.example.(com|de|fr)"-shaped, but with an actual bracketed
alternative list, e.g. "https://www.vidaxl.(at|be|bg|com|de|...)") -- a real, commonly-seen
bug-bounty scope-table shape for one company running the same site under many ccTLDs, which used
to have no support at all: the New Project form's shape check has no "(" "|" ")" in its allowlist,
so an entry written that way was flatly rejected, forcing the operator to type out every TLD by
hand as its own comma-separated entry.

expand_target_alternation() (agent/tools/builders/validators.py) turns one such entry into one
concrete candidate per alternative, BEFORE validate_scope_entry() ever sees it -- these tests cover
the expansion itself, then the full /api/scan path end-to-end.
"""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.tools import allowed_targets
from agent.tools.allowed_targets import is_target_allowed
from agent.tools.builders.validators import expand_target_alternation, validate_scope_entry
from projects import paths as project_paths
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")


# --- expand_target_alternation: pure expansion logic ---


def test_expand_returns_the_target_unchanged_when_there_is_no_alternation_group():
    assert expand_target_alternation("example.com") == ["example.com"]


def test_expand_a_single_group_preserves_surrounding_literal_text():
    assert expand_target_alternation("https://www.vidaxl.(at|be|com)") == [
        "https://www.vidaxl.at",
        "https://www.vidaxl.be",
        "https://www.vidaxl.com",
    ]


def test_expand_cartesian_products_multiple_groups():
    assert expand_target_alternation("(www|shop).example.(com|de)") == [
        "www.example.com",
        "www.example.de",
        "shop.example.com",
        "shop.example.de",
    ]


def test_expand_leaves_a_parenthesized_group_with_no_pipe_untouched():
    """A stray "(see notes)" in free text (Out-of-scope field) is not an alternation -- must not
    be torn apart or have its parens dropped."""
    assert expand_target_alternation("example.com (see notes)") == ["example.com (see notes)"]


def test_expand_rejects_a_pathologically_large_combination_count():
    huge_group = "|".join(f"opt{i}" for i in range(30))
    with pytest.raises(ValueError):
        expand_target_alternation(f"a.({huge_group}).b.({huge_group}).c")


def test_expanded_entries_each_pass_validate_scope_entry():
    for entry in expand_target_alternation("https://www.vidaxl.(at|be|bg|com|de)"):
        assert validate_scope_entry(entry) == entry


# --- /api/scan: end-to-end, same pattern as test_wildcard_scope.py's _post_scan ---


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _post_scan(tmp_path, monkeypatch, **form_overrides):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)
    form = {"name": "Alternation Scope Project", "target": "example.com", "authorize_exploit": "on"}
    form.update(form_overrides)
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    try:
        return client.post("/api/scan", data=form, follow_redirects=False)
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_scan_form_expands_a_ccTLD_alternation_target_into_every_authorized_host(tmp_path, monkeypatch):
    resp = _post_scan(tmp_path, monkeypatch, target="https://www.vidaxl.(at|be|com|de)")
    assert resp.status_code == 303, resp.text
    assert is_target_allowed("https://www.vidaxl.at") is True
    assert is_target_allowed("https://www.vidaxl.be") is True
    assert is_target_allowed("https://www.vidaxl.com") is True
    assert is_target_allowed("https://www.vidaxl.de") is True
    assert is_target_allowed("https://www.vidaxl.jp") is False


def test_scan_form_rejects_an_alternation_target_with_too_many_combinations(tmp_path, monkeypatch):
    huge_group = "|".join(f"opt{i}" for i in range(30))
    resp = _post_scan(tmp_path, monkeypatch, target=f"a.({huge_group}).b.({huge_group}).c")
    assert resp.status_code == 400
    assert "too many combinations" in resp.text


def test_scan_form_expands_alternation_alongside_a_plain_comma_separated_target(tmp_path, monkeypatch):
    resp = _post_scan(tmp_path, monkeypatch, target="other.example.com, www.vidaxl.(at|be)")
    assert resp.status_code == 303, resp.text
    assert is_target_allowed("other.example.com") is True
    assert is_target_allowed("www.vidaxl.at") is True
    assert is_target_allowed("www.vidaxl.be") is True


def test_scan_form_expands_alternation_in_out_of_scope_field_too(tmp_path, monkeypatch):
    from agent.tools.allowed_targets import is_target_out_of_scope

    resp = _post_scan(
        tmp_path,
        monkeypatch,
        target="vidaxl.com",
        out_of_scope="staging.vidaxl.(at|be)",
    )
    assert resp.status_code == 303, resp.text
    session_id = resp.headers["location"].rsplit("/", 1)[-1]
    session = store.load_session(session_id)
    assert is_target_out_of_scope("staging.vidaxl.at", session["out_of_scope"]) is True
    assert is_target_out_of_scope("staging.vidaxl.be", session["out_of_scope"]) is True
