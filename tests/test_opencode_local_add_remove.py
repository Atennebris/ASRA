"""opencode-local must behave exactly like every other provider's own explicit opt-in: invisible
everywhere (main picker, its own Settings card, Reserve providers/secondary verification) until
the operator explicitly adds it via "+ Add Provider" -- never auto-visible just because the CLI
happens to be installed. Real, confirmed operator complaint this fixes: an earlier version showed
it unconditionally in the main picker and in subagent/library pickers with no way to add/remove it
from the "// Providers" list at all, breaking the "I control what shows up by adding it myself"
expectation every other provider already gives. SETTINGS_PATH/CUSTOM_PROVIDERS_PATH isolation is
global (tests/conftest.py's own autouse fixture) -- no per-test setup needed for that here.
"""
from fastapi.testclient import TestClient

import main
from agent.llm_client import OPENCODE_LOCAL_PROVIDER_ID
from agent.settings import get_added_providers


def _patch_which(monkeypatch, found: bool):
    monkeypatch.setattr("shutil.which", lambda name: ("/usr/local/bin/opencode" if found else None) if name == "opencode" else None)


def test_not_offered_in_add_provider_dropdown_when_cli_missing(monkeypatch):
    _patch_which(monkeypatch, found=False)
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert resp.status_code == 200
    idx = resp.text.index('<option value="opencode-local"')
    tag = resp.text[idx : idx + 120]
    assert "disabled" in tag
    assert "not installed" in tag


def test_offered_in_add_provider_dropdown_when_cli_found(monkeypatch):
    _patch_which(monkeypatch, found=True)
    client = TestClient(main.app)
    resp = client.get("/settings")
    idx = resp.text.index('<option value="opencode-local"')
    tag = resp.text[idx : idx + 60]
    assert "disabled" not in tag


def test_not_in_main_picker_or_own_card_before_adding(monkeypatch):
    _patch_which(monkeypatch, found=True)
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert "Local dependency" not in resp.text
    main_picker = resp.text[resp.text.index("AI Provider &amp; Model") : resp.text.index("AI Provider &amp; Model") + 3000]
    assert "opencode (local server)" not in main_picker


def test_add_provider_route_rejects_when_cli_missing(monkeypatch):
    _patch_which(monkeypatch, found=False)
    client = TestClient(main.app)
    resp = client.post("/api/settings/providers/custom", data={"type": "opencode-local"})
    assert resp.status_code == 400
    assert "not installed" in resp.text
    assert OPENCODE_LOCAL_PROVIDER_ID not in get_added_providers()


def test_add_then_visible_everywhere_then_remove_then_gone(monkeypatch):
    _patch_which(monkeypatch, found=True)
    client = TestClient(main.app)

    resp = client.post("/api/settings/providers/custom", data={"type": "opencode-local"}, follow_redirects=False)
    assert resp.status_code == 303
    assert OPENCODE_LOCAL_PROVIDER_ID in get_added_providers()

    resp = client.get("/settings")
    assert "Local dependency" in resp.text
    main_picker = resp.text[resp.text.index("AI Provider &amp; Model") : resp.text.index("AI Provider &amp; Model") + 3000]
    assert "opencode (local server)" in main_picker
    # The card's own Remove button must actually exist now that it's added.
    assert "/api/settings/providers/opencode-local/remove" in resp.text

    resp = client.post("/api/settings/providers/opencode-local/remove", follow_redirects=False)
    assert resp.status_code == 303
    assert OPENCODE_LOCAL_PROVIDER_ID not in get_added_providers()

    resp = client.get("/settings")
    assert "Local dependency" not in resp.text


def test_remove_hides_the_card_even_while_still_the_active_provider(monkeypatch):
    """Real, confirmed operator complaint this fixes: clicking Remove genuinely un-added
    opencode-local every time (the debug log showed it succeeding three separate clicks in a row),
    but the card kept reappearing anyway because opencode-local was still the saved AI Provider &
    Model choice -- the dropdown selection had been changed client-side but never actually saved
    (that needs its own explicit Save click). opencode_local_added (main.py) must NOT exempt the
    active provider the way added_local_provider_ids (the dropdown) still does -- Remove is a
    deliberate, explicit action and must make the card go away, full stop, while the dropdown
    keeps showing opencode-local selected via its own, separate exemption."""
    _patch_which(monkeypatch, found=True)
    client = TestClient(main.app)

    resp = client.post("/api/settings/providers/custom", data={"type": "opencode-local"}, follow_redirects=False)
    assert resp.status_code == 303
    main.save_llm_settings(OPENCODE_LOCAL_PROVIDER_ID, "big-pickle")

    resp = client.post("/api/settings/providers/opencode-local/remove", follow_redirects=False)
    assert resp.status_code == 303
    assert OPENCODE_LOCAL_PROVIDER_ID not in get_added_providers()

    resp = client.get("/settings")
    assert "Local dependency" not in resp.text
    # The main picker's own dropdown still shows it selected -- removing the card never touches
    # the saved provider/model choice itself, only this card's own visibility.
    main_picker = resp.text[resp.text.index("AI Provider &amp; Model") : resp.text.index("AI Provider &amp; Model") + 3000]
    assert "opencode (local server)" in main_picker


def test_removing_a_never_added_opencode_local_is_a_safe_no_op(monkeypatch):
    """Delete on a provider id that was never actually added (nothing to clear/remove) must not
    crash -- same "safe, honest no-op" contract provider_row()'s own Delete button documents for
    a registry built-in with nothing customized."""
    _patch_which(monkeypatch, found=True)
    client = TestClient(main.app)
    resp = client.post("/api/settings/providers/opencode-local/remove", follow_redirects=False)
    assert resp.status_code == 303
    assert OPENCODE_LOCAL_PROVIDER_ID not in get_added_providers()
