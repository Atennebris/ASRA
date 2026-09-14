"""main.py's Settings-page wordlist routes: GET /settings' wordlist context, and the two
human-triggered POST actions (download a wordlist by URL, assign one to a tool role). Neither
POST route has a ToolSpec registration -- the LLM agent can never reach them, only the operator
clicking the Settings UI.
"""
import httpx
from fastapi.testclient import TestClient

import main
from agent.tools import wordlist_catalog, wordlist_download, wordlist_store

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")
    monkeypatch.setattr(wordlist_download, "DOWNLOAD_DIR", tmp_path / "wordlists")
    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (tmp_path / "no-such-scan-root",))


def test_get_settings_renders_the_wordlists_section(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Wordlists" in resp.text
    assert "Download wordlist" in resp.text


def test_download_route_rejects_a_blank_url(tmp_path, monkeypatch):
    """Real incident this guards: settings.html's Reserve providers section (added alongside the
    wordlist download form on the same page) embeds its own provider/model data via a custom
    "tojson" filter -- this error re-render used to omit that section's own context entirely,
    leaving Jinja's Undefined sentinel where real data belonged, and json.dumps(Undefined) raised
    TypeError with no graceful fallback, crashing this whole route with a 500 instead of the
    expected 400 validation message."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/wordlists/download", data={"source_url": ""})

    assert resp.status_code == 400
    assert "Enter a URL" in resp.text
    assert "Reserve providers" in resp.text


def test_download_route_shows_a_clean_error_for_a_bad_scheme(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/wordlists/download", data={"source_url": "ftp://example.com/x.txt"})

    assert resp.status_code == 400
    assert "http" in resp.text


def test_download_route_succeeds_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"admin\nroot\n")

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(handler))
    client = TestClient(main.app)

    resp = client.post(
        "/api/settings/wordlists/download",
        data={"source_url": "https://example.com/users.txt", "name": "", "kind": "usernames"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/settings"
    store = wordlist_store.load_wordlist_store()
    assert store["downloaded"][0]["kind"] == "usernames"

    page = client.get("/settings")
    assert "users.txt" in page.text


def test_assign_route_rejects_an_unknown_role(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/wordlists/assign", data={"role": "not_a_real_role", "path": "/tmp/x.txt"})

    assert resp.status_code == 400


def test_assign_route_persists_and_clears(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    real_file = tmp_path / "list.txt"
    real_file.write_text("a\n", encoding="utf-8")

    resp = client.post(
        "/api/settings/wordlists/assign",
        data={"role": "hydra_usernames", "path": str(real_file)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert wordlist_store.get_assigned_wordlist("hydra_usernames") == str(real_file)

    client.post("/api/settings/wordlists/assign", data={"role": "hydra_usernames", "path": ""})
    assert wordlist_store.get_assigned_wordlist("hydra_usernames") is None
