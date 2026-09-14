"""HTTP routes behind the Library panel (main.py's /api/library/* -- upload, source list,
chunk estimate, analyze, delete) -- agent/tools/library_store.py's own unit tests already cover
the underlying logic; these pin the routes' request/response shape and wiring.
"""
import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import library_store
from agent.tools import playbook_store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(library_store, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")


def test_library_sources_delete_and_analyze_sync_against_the_self_poll():
    """Regression guard for a real, confirmed-live bug: the self-poll (active while any source is
    "analyzing") and a manual delete/analyze/upload all swap the exact same #library-sources via
    outerHTML with no coordination -- a poll response dispatched BEFORE a delete could land AFTER
    the delete's own response and silently restore the "deleted" card, reading as "delete doesn't
    always work" when it had, in fact, already succeeded server-side. Live-verified via a real
    headless-browser reproduction (delete a card while a different one polls as "analyzing" across
    2+ real poll ticks -- stays deleted); this only guards the fix's own attributes don't quietly
    disappear later, since pytest's TestClient never executes htmx's client-side coordination."""
    library_store.add_source(b"content one", "a.txt", title="Source A")
    library_store.add_source(b"content two", "b.txt", title="Source B")
    client = TestClient(main.app)

    resp = client.get("/api/library/sources")

    assert resp.text.count('hx-sync="#library-sources:replace"') == 4  # 2 sources x (delete + analyze)


def test_library_upload_forms_sync_against_the_self_poll():
    resp = TestClient(main.app).get("/playbook")
    assert resp.text.count('hx-sync="#library-sources:replace"') == 2  # file-upload form + URL-upload form


def test_library_upload_route_normalizes_and_returns_source_list():
    client = TestClient(main.app)

    resp = client.post(
        "/api/library/upload",
        files={"file": ("notes.txt", b"Some real content here.", "text/plain")},
        data={"title": "My Notes", "author": "Me"},
    )

    assert resp.status_code == 200
    assert "My Notes" in resp.text
    sources = library_store.list_sources()
    assert len(sources) == 1
    assert sources[0]["status"] == "normalized"


def test_library_upload_route_rejects_unsupported_format():
    client = TestClient(main.app)

    resp = client.post(
        "/api/library/upload",
        files={"file": ("malware.exe", b"junk", "application/octet-stream")},
    )

    assert resp.status_code == 200
    assert "Unsupported" in resp.text
    assert library_store.list_sources() == []


def test_library_upload_route_flags_duplicate_content_and_add_anyway_proceeds():
    client = TestClient(main.app)
    client.post("/api/library/upload", files={"file": ("first.txt", b"identical content here", "text/plain")})

    resp = client.post("/api/library/upload", files={"file": ("second.txt", b"identical content here", "text/plain")})

    assert resp.status_code == 200
    assert "Add anyway" in resp.text
    assert "same material as" in resp.text
    sources = {s["filename"]: s for s in library_store.list_sources()}
    assert sources["first.txt"]["status"] == "normalized"
    dup_id = sources["second.txt"]["id"]
    assert sources["second.txt"]["status"] == "duplicate_pending"

    resp2 = client.post(f"/api/library/{dup_id}/confirm-duplicate")

    assert resp2.status_code == 200
    assert library_store.get_source(dup_id)["status"] == "normalized"


def test_library_card_shows_a_visible_source_id():
    client = TestClient(main.app)
    resp = client.post("/api/library/upload", files={"file": ("notes.txt", b"Some real content here.", "text/plain")})

    sid = library_store.list_sources()[0]["id"]
    assert f"#{sid[:8]}" in resp.text


def test_library_upload_url_route_fetches_and_returns_source_list(monkeypatch):
    class _FakeResponse:
        headers = {"content-type": "text/html"}

        def raise_for_status(self):
            pass

        def iter_bytes(self):
            # Long enough to clear _MIN_HTML_CHARS_BEFORE_BROWSER_FALLBACK -- this test isn't
            # about the browser-fallback path (library_store's own tests cover that), so it
            # shouldn't accidentally trigger a real Playwright launch by looking like a thin shell.
            yield b"<html><body><p>" + b"A real technique from a web page. " * 6 + b"</p></body></html>"

    class _FakeStream:
        def __enter__(self):
            return _FakeResponse()

        def __exit__(self, *a):
            return False

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def stream(self, method, url):
            return _FakeStream()

    monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient())
    client = TestClient(main.app)

    resp = client.post("/api/library/upload-url", data={"url": "https://example.com/writeup", "title": "Web Doc"})

    assert resp.status_code == 200
    assert "Web Doc" in resp.text
    sources = library_store.list_sources()
    assert len(sources) == 1
    assert sources[0]["source_url"] == "https://example.com/writeup"


def test_library_upload_url_route_shows_via_browser_badge_after_a_real_fallback(monkeypatch):
    """Regression guard for a real operator complaint: the browser-automation fallback inside
    add_source_from_url already worked, but nothing in the UI ever showed it had happened --
    visible only in debug.log. The card must surface it once fetched_via=="browser"."""
    monkeypatch.setattr("agent.tools.library_store._fetch_via_httpx", lambda url: None)
    rendered_html = b"<html><body><p>" + b"A real technique from a rendered page. " * 6 + b"</p></body></html>"
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: rendered_html)
    client = TestClient(main.app)

    resp = client.post("/api/library/upload-url", data={"url": "https://blocked.example/writeup"})

    assert resp.status_code == 200
    assert "via browser" in resp.text
    assert library_store.list_sources()[0]["fetched_via"] == "browser"


def test_library_upload_url_route_shows_no_badge_for_a_plain_httpx_fetch(monkeypatch):
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: (_ for _ in ()).throw(AssertionError("must not be called")))
    # Long enough to clear _MIN_HTML_CHARS_BEFORE_BROWSER_FALLBACK -- this test is specifically
    # about the plain-httpx-succeeded path never touching the browser fallback at all.
    monkeypatch.setattr(
        "agent.tools.library_store._fetch_via_httpx",
        lambda url: (b"<html><body><p>" + b"A real plain-fetch technique. " * 12 + b"</p></body></html>", "text/html"),
    )
    client = TestClient(main.app)

    resp = client.post("/api/library/upload-url", data={"url": "https://example.com/writeup"})

    assert resp.status_code == 200
    assert "via browser" not in resp.text
    assert library_store.list_sources()[0]["fetched_via"] is None


def test_library_upload_url_route_rejects_bad_url():
    client = TestClient(main.app)

    resp = client.post("/api/library/upload-url", data={"url": "not-a-url"})

    assert resp.status_code == 200
    assert "fetch that URL" in resp.text  # HTML-escapes the apostrophe in "Couldn't", so match around it
    assert library_store.list_sources() == []


def test_library_sources_route_lists_uploaded_sources():
    library_store.add_source(b"content", "a.txt", title="A")
    client = TestClient(main.app)

    resp = client.get("/api/library/sources")

    assert resp.status_code == 200
    assert "A" in resp.text


def test_library_delete_route_removes_source():
    sid = library_store.add_source(b"content", "a.txt", title="A")
    client = TestClient(main.app)

    resp = client.post(f"/api/library/{sid}/delete")

    assert resp.status_code == 200
    assert library_store.get_source(sid) is None


def test_library_sources_analyzed_card_links_to_playbook_review(monkeypatch):
    """A real, confirmed operator complaint: after analysis finished, the "Analyzed -- N technique(s)
    extracted" line was a dead end with no way to actually go look at what got extracted. This
    link closes the panel and flips the Playbook toolbar's own confidence filter to "unreviewed"
    (client-side JS, same select the toolbar's own htmx wiring already reads) instead of building
    a second, separate review surface."""
    sid = library_store.add_source(b"content", "a.txt")
    llm = type("Fake", (), {
        "context_limit": 100_000, "provider_id": "fake", "model": "fake-model",
        "complete": lambda self, messages, tools, stop_check=None: type("R", (), {
            "content": '[{"technique": "X", "tech_keywords": ["mysql"], "waf_vendors": []}]',
        })(),
        "embed": lambda self, texts, model: None,
    })()
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)
    client = TestClient(main.app)

    client.post(f"/api/library/{sid}/analyze", data={"provider": "fake", "model": "fake-model"})
    resp = client.get("/api/library/sources")

    assert "Review in Playbook" in resp.text
    assert "select[name=confidence]" in resp.text  # the exact toolbar select it targets client-side


def test_library_sources_estimate_span_has_its_own_explicit_hx_target():
    """Regression guard for a real, confirmed-live bug: the
    per-source chunk-estimate span is nested inside a <form> that sets hx-target="#library-sources"
    for its OWN hx-post -- htmx attribute inheritance means the span's own hx-get silently inherits
    that same target unless it sets an explicit one, which collapsed the whole source list down to
    the bare estimate text the instant it fired. Only a real browser can execute htmx and reproduce
    the actual failure; this at least keeps the fix (an explicit override) from silently regressing."""
    library_store.add_source(b"Some content.", "a.txt")
    client = TestClient(main.app)

    resp = client.get("/api/library/sources")

    assert 'hx-get="/api/library/' in resp.text and '/estimate"' in resp.text
    assert 'hx-target="this"' in resp.text


def test_library_estimate_route_returns_a_chunk_count_label():
    sid = library_store.add_source(b"Some content to estimate against.", "a.txt")
    client = TestClient(main.app)

    resp = client.get(f"/api/library/{sid}/estimate", params={"provider": "", "model": ""})

    assert resp.status_code == 200
    assert "chunk" in resp.text


def test_library_estimate_route_flags_when_over_the_chunk_limit(monkeypatch):
    monkeypatch.setattr(library_store, "_MAX_CHUNKS", 1)
    # A tiny context_limit, mocked rather than relying on whatever this machine's real Settings
    # default provider happens to resolve to -- guarantees 2+ chunks regardless of environment.
    fake_llm = type("Fake", (), {"context_limit": 200})()
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: fake_llm)
    sid = library_store.add_source((b"Paragraph.\n\n" * 5000), "a.txt")
    client = TestClient(main.app)

    resp = client.get(f"/api/library/{sid}/estimate", params={"provider": "fake", "model": "fake-model"})

    assert resp.status_code == 200
    assert "over the" in resp.text and "limit" in resp.text


def test_library_analyze_route_runs_the_pipeline_and_ingests_into_playbook(monkeypatch):
    sid = library_store.add_source(b"A paragraph describing a real SQLi bypass technique.", "book.txt")

    class _FakeLLM:
        provider_id = "fake"
        model = "fake-model"
        context_limit = 100_000

        def complete(self, messages, tools, stop_check=None):
            class _R:
                content = '[{"technique": "SQLi bypass", "tech_keywords": ["mysql"], "waf_vendors": []}]'
            return _R()

        def embed(self, texts, model):
            return None

    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: _FakeLLM())
    client = TestClient(main.app)

    resp = client.post(f"/api/library/{sid}/analyze", data={"provider": "fake", "model": "fake-model"})

    assert resp.status_code == 200
    # The route only SCHEDULES the analysis (fire-and-forget) -- TestClient's own event loop
    # keeps running the same in-process task between requests, so it reliably finishes by the
    # time this second request comes in, same as a real browser polling /api/library/sources.
    resp2 = client.get("/api/library/sources")
    assert "extracted" in resp2.text.lower() or "analyzed" in resp2.text.lower()
    store = playbook_store.load_playbook_store()
    entry = next(iter(store.values()))[0]
    assert entry["confidence"] == "unreviewed"
    assert entry["source_type"] == "extracted"


def test_library_analyze_route_first_response_already_shows_analyzing(monkeypatch):
    """Regression guard for a real, confirmed-live bug: the
    route used to render this same response BEFORE the fire-and-forget background task got any
    chance to run, so the very first Analyze click's own response still showed the OLD
    "Ready to analyze" card with no self-poll attached -- looking like the click did nothing until
    a second click's response happened to catch the by-then-real "analyzing" status. Confirmed
    live via debug.log timestamps (a "start_analysis accepted" line followed ~3.6s later by a
    second "refused ... already analyzing" line for the same source). The fix moved the
    status="analyzing" write into the synchronous half of start_analysis, so it must already be
    present in THIS FIRST response, before the background task has run a single chunk."""
    sid = library_store.add_source(b"A paragraph describing a real SQLi bypass technique.", "book.txt")

    class _FakeLLM:
        provider_id = "fake"
        model = "fake-model"
        context_limit = 100_000

        def complete(self, messages, tools, stop_check=None):
            class _R:
                content = "[]"
            return _R()

        def embed(self, texts, model):
            return None

    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: _FakeLLM())
    client = TestClient(main.app)

    resp = client.post(f"/api/library/{sid}/analyze", data={"provider": "fake", "model": "fake-model"})

    assert resp.status_code == 200
    assert "Analyzing" in resp.text
    assert f'hx-get="/api/library/{sid}/card"' in resp.text and "every 2s" in resp.text


def test_library_analyze_route_surfaces_the_concurrency_refusal_message(monkeypatch):
    sid = library_store.add_source(b"content", "a.txt")
    monkeypatch.setattr(library_store, "start_analysis", lambda source_id, provider, model: "1 analysis run(s) already in progress (limit 1) -- wait for one to finish first")
    client = TestClient(main.app)

    resp = client.post(f"/api/library/{sid}/analyze", data={"provider": "", "model": ""})

    assert resp.status_code == 200
    assert "already in progress" in resp.text


# --- per-card route + self-poll ---


def test_library_card_route_returns_just_that_one_card():
    sid = library_store.add_source(b"content", "a.txt")
    client = TestClient(main.app)

    resp = client.get(f"/api/library/{sid}/card")

    assert resp.status_code == 200
    assert f'id="library-card-{sid}"' in resp.text
    assert "Ready to analyze" in resp.text


def test_library_card_route_404s_for_unknown_source():
    client = TestClient(main.app)
    resp = client.get("/api/library/nope/card")
    assert resp.status_code == 404


def test_only_the_analyzing_card_carries_its_own_self_poll():
    """Regression guard for a real, confirmed-live flicker bug: the OLD
    self-poll lived on the whole #library-sources list, so every 2s tick re-swapped every card
    including ones that weren't analyzing, re-firing their own estimate span's "load" trigger for
    no reason. Each card must carry its own poll ONLY while its own status=="analyzing"."""
    normalized_id = library_store.add_source(b"content one", "a.txt")
    analyzing_id = library_store.add_source(b"content two", "b.txt")
    library_store._update_source(analyzing_id, status="analyzing", chunks_total=3, chunks_done=1)
    client = TestClient(main.app)

    resp = client.get("/api/library/sources")

    assert f'id="library-card-{analyzing_id}"' in resp.text
    assert f'hx-get="/api/library/{analyzing_id}/card" hx-trigger="every 2s"' in resp.text
    assert f'hx-get="/api/library/{normalized_id}/card"' not in resp.text
    # The OLD whole-list poll must be gone entirely.
    assert 'hx-get="/api/library/sources" hx-trigger="every 2s"' not in resp.text


def test_analyzing_card_shows_a_stop_button():
    sid = library_store.add_source(b"content", "a.txt")
    library_store._update_source(sid, status="analyzing", chunks_total=3, chunks_done=1)
    client = TestClient(main.app)

    resp = client.get(f"/api/library/{sid}/card")

    assert f'hx-post="/api/library/{sid}/stop-analysis"' in resp.text
    assert "Stop" in resp.text


# --- stop-analysis route ---


def test_stop_analysis_route_reports_nothing_running():
    sid = library_store.add_source(b"content", "a.txt")
    client = TestClient(main.app)

    resp = client.post(f"/api/library/{sid}/stop-analysis")

    assert resp.status_code == 200
    assert "Nothing is currently running" in resp.text


def test_stop_analysis_route_stops_a_real_running_analysis(monkeypatch):
    # The real cancel-a-genuinely-running-task behavior is already covered end-to-end by
    # test_library_store.py's own test_stop_analysis_cancels_a_running_task_and_keeps_completed_
    # chunk_results (which needs a real event loop it controls throughout) -- this route test only
    # needs to confirm the route itself calls stop_analysis and reflects a True result correctly.
    sid = library_store.add_source(b"content", "a.txt")
    monkeypatch.setattr(library_store, "stop_analysis", lambda source_id: True)
    client = TestClient(main.app)

    resp = client.post(f"/api/library/{sid}/stop-analysis")

    assert resp.status_code == 200
    assert "Nothing is currently running" not in resp.text


# --- running-analyses count in the panel ---


def test_library_sources_shows_running_count_and_max_label():
    library_store.add_source(b"content", "a.txt")
    client = TestClient(main.app)

    resp = client.get("/api/library/sources")

    assert "Analyses running: 0 /" in resp.text


def test_library_sources_shows_infinity_when_unlimited(monkeypatch):
    monkeypatch.setattr(library_store, "_MAX_CONCURRENT_ANALYSES", 0)
    library_store.add_source(b"content", "a.txt")
    client = TestClient(main.app)

    resp = client.get("/api/library/sources")

    assert "Analyses running: 0 / ∞" in resp.text


# --- estimate route N/MAX format ---


def test_library_estimate_route_shows_max_even_when_not_over(monkeypatch):
    fake_llm = type("Fake", (), {"context_limit": 100_000})()
    monkeypatch.setattr(library_store, "get_provider", lambda p, m: fake_llm)
    sid = library_store.add_source(b"Some short content.", "a.txt")
    client = TestClient(main.app)

    resp = client.get(f"/api/library/{sid}/estimate", params={"provider": "fake", "model": "fake-model"})

    assert f"/ {library_store._MAX_CHUNKS} chunk" in resp.text


# --- Library's own model-options endpoint (picker remembering its own last-used model) ---


def test_library_model_options_preselects_librarys_own_saved_model():
    """Regression guard for a real, confirmed-live bug: switching provider
    in the Library panel's picker used to always reset the model to that provider's generic
    hardcoded default (or Settings' own unrelated main-agent model), discarding whatever model the
    operator had actually used with THIS provider in the Library before. Confirmed live against the
    operator's own real data: library_store had last_provider="openrouter"/
    last_model="nvidia/nemotron-3-ultra-550b-a55b:free" saved, but /api/subagents/model-options
    still marked "openrouter/auto" (the provider's own hardcoded default) selected instead."""
    library_store.save_last_analysis_llm("openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free")
    client = TestClient(main.app)

    resp = client.get("/api/library/model-options", params={"provider": "openrouter"})

    assert resp.status_code == 200
    assert 'value="nvidia/nemotron-3-ultra-550b-a55b:free" selected' in resp.text


def test_library_model_options_falls_back_to_provider_default_with_nothing_saved():
    client = TestClient(main.app)

    resp = client.get("/api/library/model-options", params={"provider": "openrouter"})

    assert resp.status_code == 200
    assert "selected" in resp.text  # some option is still marked selected -- never an empty select


def test_library_model_options_ignores_a_different_providers_saved_model():
    # last_model was saved for a DIFFERENT provider -- must not leak across providers.
    library_store.save_last_analysis_llm("opencode-zen", "some-opencode-model")
    client = TestClient(main.app)

    resp = client.get("/api/library/model-options", params={"provider": "openrouter"})

    assert resp.status_code == 200
    assert "some-opencode-model" not in resp.text


def test_library_model_options_blank_provider_returns_same_as_main_agent_placeholder():
    client = TestClient(main.app)

    resp = client.get("/api/library/model-options", params={"provider": ""})

    assert resp.status_code == 200
    assert "(same as main agent)" in resp.text


# --- last-used provider/model pre-filled on /playbook ---


def test_playbook_page_prefills_the_shared_picker_from_saved_settings():
    library_store.save_last_analysis_llm("opencode-zen", "big-pickle")
    client = TestClient(main.app)

    resp = client.get("/playbook")

    assert 'id="library-provider-shared"' in resp.text
    assert 'value="opencode-zen" selected' in resp.text
