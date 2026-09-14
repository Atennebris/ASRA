"""Knowledge-library source ingestion: agent/tools/library_store.py's storage, format
normalization (PDF/epub/txt/md), chunking, and the LLM-driven analysis pass that writes candidate
techniques into the playbook as source_type="extracted"/confidence="unreviewed".
"""
import asyncio
import json
import tempfile
import time

import pytest

from agent.tools import library_store
from agent.tools import playbook_store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    # library_store computes its own storage paths from resolve_global_app_dir() (imported by
    # name, not a fixed module-level constant the way playbook_store.PLAYBOOK_STORE_PATH is) --
    # patching the imported reference in library_store's own namespace isolates it without
    # touching that function's @lru_cache or any other module that also imports it.
    monkeypatch.setattr(library_store, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")


def _make_pdf_bytes(text: str) -> bytes:
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.multi_cell(0, 10, text)
    return bytes(pdf.output())


def _make_epub_bytes(chapters: list[str]) -> bytes:
    from ebooklib import epub
    book = epub.EpubBook()
    book.set_identifier("test-id")
    book.set_title("Test Book")
    book.add_author("Test Author")
    spine = ["nav"]
    for i, text in enumerate(chapters):
        c = epub.EpubHtml(title=f"Chapter {i + 1}", file_name=f"chap{i + 1}.xhtml", lang="en")
        c.content = f"<html><body><p>{text}</p></body></html>"
        book.add_item(c)
        spine.append(c)
    book.add_item(epub.EpubNcx())
    book.add_item(epub.EpubNav())
    book.spine = spine
    with tempfile.NamedTemporaryFile(suffix=".epub", delete=False) as tmp:
        tmp_path = tmp.name
    epub.write_epub(tmp_path, book)
    data = open(tmp_path, "rb").read()
    import os
    os.unlink(tmp_path)
    return data


# --- add_source / normalization ---


def test_add_source_txt_normalizes_and_stores_metadata():
    sid = library_store.add_source(b"Hello world.\n\nA real technique paragraph.", "notes.txt", title="My Notes", author="Me")

    source = library_store.get_source(sid)
    assert source["status"] == "normalized"
    assert source["format"] == "txt"
    assert source["title"] == "My Notes"
    assert source["author"] == "Me"
    assert source["char_count"] > 0
    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "real technique paragraph" in text


def test_add_source_md_defaults_title_to_filename_when_blank():
    sid = library_store.add_source(b"# Heading\n\nSome content.", "writeup.md")
    assert library_store.get_source(sid)["title"] == "writeup.md"


def test_add_source_pdf_extracts_text_with_page_markers():
    data = _make_pdf_bytes("Exploit technique: SQLi bypass via inline comments.")
    sid = library_store.add_source(data, "book.pdf")

    source = library_store.get_source(sid)
    assert source["status"] == "normalized"
    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "[page 1]" in text
    assert "SQLi bypass" in text


def test_add_source_epub_extracts_text_in_spine_order_with_chapter_markers():
    data = _make_epub_bytes(["First chapter about XSS.", "Second chapter about SSRF."])
    sid = library_store.add_source(data, "book.epub")

    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "[chapter 1]" in text and "XSS" in text
    assert "[chapter 2]" in text and "SSRF" in text
    assert text.index("XSS") < text.index("SSRF")  # spine (reading) order preserved


def test_add_source_rejects_unsupported_extension():
    assert library_store.add_source(b"binary junk", "malware.exe") is None


def test_add_source_empty_extractable_text_marks_error():
    # A "PDF" that's really just garbage bytes -- pypdf can't read a real page out of it, so
    # normalization succeeds (no exception) but produces nothing extractable.
    sid = library_store.add_source(b"%PDF-1.4 not a real pdf", "broken.pdf")
    source = library_store.get_source(sid)
    assert source["status"] == "error"


def test_reconcile_orphaned_analyses_flips_stuck_sources_to_error():
    """Real, confirmed operator complaint: a source clicked "Analyze" then the server restarted
    (or crashed) mid-flight stays status="analyzing" forever afterward -- nothing else ever moves
    that status forward, and the Analyze button/estimate span are BOTH gated off entirely for that
    status (see templates/partials/library_sources.html), so the operator had no way back in
    through the UI at all, not even a retry, across every future restart."""
    sid = library_store.add_source(b"content", "t.txt")
    library_store._update_source(sid, status="analyzing", chunks_total=5, chunks_done=1)

    fixed = library_store.reconcile_orphaned_analyses()

    assert fixed == 1
    source = library_store.get_source(sid)
    assert source["status"] == "error"
    assert "restarted" in source["error"]


def test_reconcile_orphaned_analyses_leaves_other_statuses_alone():
    sid = library_store.add_source(b"content", "t.txt")  # status="normalized"

    fixed = library_store.reconcile_orphaned_analyses()

    assert fixed == 0
    assert library_store.get_source(sid)["status"] == "normalized"


def test_delete_source_removes_metadata_and_files():
    sid = library_store.add_source(b"content here", "t.txt")
    assert library_store._source_dir(sid).is_dir()

    assert library_store.delete_source(sid) is True

    assert library_store.get_source(sid) is None
    assert not library_store._source_dir(sid).exists()


def test_delete_source_unknown_id_returns_false():
    assert library_store.delete_source("nope") is False


# --- add_source_from_url ---


class _FakeHttpResponse:
    def __init__(self, content, headers, ok=True):
        self._content = content
        self.headers = headers
        self._ok = ok

    def raise_for_status(self):
        if not self._ok:
            import httpx
            raise httpx.HTTPStatusError("bad status", request=None, response=None)

    def iter_bytes(self):
        # Mirrors the real streaming API's own chunking shape closely enough for the size-cap
        # test below to actually exercise the loop instead of getting one giant chunk.
        chunk_size = 1024
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i:i + chunk_size]


class _FakeStreamCtx:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self._response

    def __exit__(self, *args):
        return False


class _FakeHttpxClient:
    def __init__(self, content, headers, ok=True):
        self._content = content
        self._headers = headers
        self._ok = ok

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url):
        return _FakeStreamCtx(_FakeHttpResponse(self._content, self._headers, self._ok))


def _patch_httpx_client(monkeypatch, content: bytes, headers: dict, ok: bool = True):
    monkeypatch.setattr("httpx.Client", lambda **kw: _FakeHttpxClient(content, headers, ok))


def _patch_no_browser_fallback(monkeypatch):
    """Stubs _fetch_via_browser to return None -- every test that isn't specifically exercising
    the browser-fallback path itself uses this so it can never accidentally launch a real
    Playwright/Chromium instance (slow, unreliable in CI, and not what that test is about)."""
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: None)


# A real article's worth of text -- long enough (> _MIN_HTML_CHARS_BEFORE_BROWSER_FALLBACK) that a
# successful httpx fetch of it is never mistaken for a JS-rendered empty shell and doesn't trigger
# the browser-fallback path in tests that aren't specifically about that path.
_LONG_HTML_BODY = "<p>" + ("A real SQLi bypass technique via inline comments. " * 6) + "</p>"


def test_add_source_from_url_html_page_is_normalized(monkeypatch):
    _patch_no_browser_fallback(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        f"<html><body><script>evil()</script>{_LONG_HTML_BODY}</body></html>".encode(),
        {"content-type": "text/html; charset=utf-8"},
    )

    sid = library_store.add_source_from_url("https://example.com/writeup", title="Web Writeup")

    source = library_store.get_source(sid)
    assert source["format"] == "html"
    assert source["status"] == "normalized"
    assert source["source_url"] == "https://example.com/writeup"
    # A plain httpx fetch that just worked -- no browser fallback needed, no badge to show.
    assert source["fetched_via"] is None
    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "SQLi bypass technique" in text
    assert "evil()" not in text  # <script> content stripped


def test_add_source_from_url_pdf_detected_by_content_type(monkeypatch):
    _patch_no_browser_fallback(monkeypatch)
    pdf_bytes = _make_pdf_bytes("A technique from a fetched PDF.")
    _patch_httpx_client(monkeypatch, pdf_bytes, {"content-type": "application/pdf"})

    sid = library_store.add_source_from_url("https://example.com/download?id=1")

    source = library_store.get_source(sid)
    assert source["format"] == "pdf"
    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "fetched PDF" in text


def test_add_source_from_url_rejects_non_http_scheme():
    assert library_store.add_source_from_url("file:///etc/passwd") is None
    assert library_store.add_source_from_url("javascript:alert(1)") is None
    assert library_store.add_source_from_url("") is None


def test_add_source_from_url_fetch_failure_returns_none(monkeypatch):
    _patch_no_browser_fallback(monkeypatch)

    def _boom(**kw):
        raise ConnectionError("simulated network failure")
    monkeypatch.setattr("httpx.Client", _boom)

    assert library_store.add_source_from_url("https://unreachable.example") is None


def test_add_source_from_url_enforces_max_size(monkeypatch):
    _patch_no_browser_fallback(monkeypatch)
    huge = b"x" * (library_store._URL_MAX_BYTES + 1)
    _patch_httpx_client(monkeypatch, huge, {"content-type": "text/html"})

    assert library_store.add_source_from_url("https://example.com/huge") is None


# --- browser fallback ---


def test_add_source_from_url_falls_back_to_browser_when_httpx_fails_outright(monkeypatch):
    def _boom(**kw):
        raise ConnectionError("simulated network failure")
    monkeypatch.setattr("httpx.Client", _boom)
    rendered_html = f"<html><body>{_LONG_HTML_BODY}</body></html>".encode()
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: rendered_html)

    sid = library_store.add_source_from_url("https://bot-blocked.example/writeup")

    assert sid is not None
    source = library_store.get_source(sid)
    assert source["format"] == "html"
    assert source["fetched_via"] == "browser"
    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "SQLi bypass technique" in text


def test_add_source_from_url_falls_back_to_browser_when_httpx_content_is_a_thin_js_shell(monkeypatch):
    # A near-empty SPA shell -- exactly what a plain GET sees before client-side JS ever runs.
    _patch_httpx_client(monkeypatch, b"<html><body><div id='root'></div></body></html>", {"content-type": "text/html"})
    rendered_html = f"<html><body>{_LONG_HTML_BODY}</body></html>".encode()
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: rendered_html)

    sid = library_store.add_source_from_url("https://spa.example/writeup")

    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "SQLi bypass technique" in text  # the RENDERED content, not the empty shell
    assert library_store.get_source(sid)["fetched_via"] == "browser"


def test_add_source_from_url_keeps_thin_httpx_content_when_browser_fallback_also_fails(monkeypatch):
    _patch_httpx_client(monkeypatch, b"<html><body><p>short</p></body></html>", {"content-type": "text/html"})
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: None)

    sid = library_store.add_source_from_url("https://spa.example/writeup")

    # Both paths tried, both this thin -- still creates a source from whatever httpx got rather
    # than failing outright; a thin real result beats no result at all.
    assert sid is not None
    text = (library_store._source_dir(sid) / "source.txt").read_text(encoding="utf-8")
    assert "short" in text
    # Browser fallback was TRIED but failed -- what's kept is still the plain httpx result, so no
    # "via browser" badge should show for content that browser automation never actually produced.
    assert library_store.get_source(sid)["fetched_via"] is None


def test_add_source_from_url_returns_none_when_both_fetch_paths_fail(monkeypatch):
    def _boom(**kw):
        raise ConnectionError("simulated network failure")
    monkeypatch.setattr("httpx.Client", _boom)
    monkeypatch.setattr(library_store, "_fetch_via_browser", lambda url: None)

    assert library_store.add_source_from_url("https://totally-unreachable.example") is None


def test_list_sources_newest_first():
    a = library_store.add_source(b"a", "a.txt")
    b = library_store.add_source(b"b", "b.txt")
    ids = [s["id"] for s in library_store.list_sources()]
    assert ids == [b, a]


# --- content-hash duplicate detection ---


def test_add_source_same_bytes_twice_holds_second_at_duplicate_pending():
    # Real, direct operator ask: the exact same material (byte-identical, even under a different
    # filename) re-uploaded should be flagged, not silently normalized as an indistinguishable
    # second copy.
    first_id = library_store.add_source(b"identical content here", "first-name.txt")
    second_id = library_store.add_source(b"identical content here", "second-name.txt")

    first = library_store.get_source(first_id)
    second = library_store.get_source(second_id)
    assert first["status"] == "normalized"  # the ORIGINAL upload proceeds completely normally
    assert second["status"] == "duplicate_pending"
    assert second["duplicate_of_id"] == first_id
    assert second["duplicate_of_title"] == first["title"]
    assert not (library_store._source_dir(second_id) / "source.txt").exists()  # never normalized


def test_add_source_different_bytes_never_flagged_as_duplicate():
    library_store.add_source(b"content A", "a.txt")
    second_id = library_store.add_source(b"content B", "b.txt")
    assert library_store.get_source(second_id)["status"] == "normalized"


def test_confirm_duplicate_upload_proceeds_with_the_bytes_already_on_disk():
    first_id = library_store.add_source(b"identical content here", "first.txt")
    second_id = library_store.add_source(b"identical content here", "second.txt")

    ok = library_store.confirm_duplicate_upload(second_id)

    assert ok is True
    second = library_store.get_source(second_id)
    assert second["status"] == "normalized"
    assert second["char_count"] > 0
    # The original stays completely untouched by the operator's later choice to also keep the dup.
    assert library_store.get_source(first_id)["status"] == "normalized"


def test_confirm_duplicate_upload_refuses_a_source_thats_not_duplicate_pending():
    sid = library_store.add_source(b"some content", "a.txt")
    assert library_store.confirm_duplicate_upload(sid) is False  # already "normalized", not pending
    assert library_store.confirm_duplicate_upload("nonexistent-id") is False


def test_add_source_from_url_also_detects_duplicate_content(monkeypatch):
    _patch_no_browser_fallback(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        f"<html><body>{_LONG_HTML_BODY}</body></html>".encode(),
        {"content-type": "text/html"},
    )
    first_id = library_store.add_source_from_url("https://example.com/writeup")
    second_id = library_store.add_source_from_url("https://example.com/writeup-mirror")

    assert library_store.get_source(second_id)["status"] == "duplicate_pending"
    assert library_store.get_source(second_id)["duplicate_of_id"] == first_id


# --- chunking ---


def test_split_into_chunks_keeps_paragraphs_whole_with_light_overlap():
    text = "para one.\n\npara two.\n\npara three."
    chunks = library_store._split_into_chunks(text, chunk_chars=15)
    assert chunks == ["para one.", "para one.\n\npara two.", "para two.\n\npara three."]


def test_split_into_chunks_hard_splits_a_paragraph_bigger_than_the_whole_budget():
    huge = "x" * 50
    chunks = library_store._split_into_chunks(huge, chunk_chars=20)
    assert len(chunks) == 3
    assert "".join(chunks) == huge


def test_split_into_chunks_empty_text_returns_empty_list():
    assert library_store._split_into_chunks("   \n\n  ", chunk_chars=100) == []


def test_chunk_char_budget_uses_default_when_context_limit_unknown():
    default_budget = library_store._chunk_char_budget(None)
    explicit_budget = library_store._chunk_char_budget(library_store._DEFAULT_CONTEXT_LIMIT_TOKENS)
    assert default_budget == explicit_budget


def test_chunk_char_budget_scales_with_context_limit():
    small = library_store._chunk_char_budget(2000)
    large = library_store._chunk_char_budget(200000)
    assert large > small


def test_estimate_chunk_count_falls_back_to_default_budget_when_provider_unresolvable(monkeypatch):
    sid = library_store.add_source(b"para one.\n\npara two.", "t.txt")

    def _boom(provider_id, model):
        raise ValueError("no api key configured")
    monkeypatch.setattr(library_store, "get_provider", _boom)

    # Must not raise -- an unconfigured provider degrades to the default chunk budget instead of
    # crashing the estimate the operator sees before even clicking Analyze.
    count = library_store.estimate_chunk_count(sid, "some-provider", "some-model")
    assert count >= 1


def test_estimate_chunk_count_unknown_source_is_zero():
    assert library_store.estimate_chunk_count("nope", "p", "m") == 0


# --- analysis pipeline (mocked LLM, no real network) ---


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    provider_id = "fake"
    model = "fake-model"

    def __init__(self, context_limit=1000, extraction_replies=None, embed_result=None, fail_on=None):
        self.context_limit = context_limit
        self._extraction_replies = list(extraction_replies or [])
        self._embed_result = embed_result
        self._fail_on = fail_on or set()
        self.calls = 0

    def complete(self, messages, tools, stop_check=None):
        self.calls += 1
        user_content = messages[-1]["content"]
        if user_content.startswith("["):  # the merge pass gets the candidates JSON as its user message
            return _FakeResponse(user_content)
        if self.calls in self._fail_on:
            raise RuntimeError("simulated provider failure")
        reply = self._extraction_replies.pop(0) if self._extraction_replies else "[]"
        return _FakeResponse(reply)

    def embed(self, texts, model):
        return self._embed_result


def _run(coro):
    return asyncio.run(coro)


def test_run_analysis_single_chunk_ingests_extracted_technique(monkeypatch):
    sid = library_store.add_source(b"A paragraph describing a SQLi bypass technique.", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=[json.dumps([
        {"technique": "SQLi comment bypass", "vuln_class": "sqli", "payload_or_command": "/*!50000UNION*/",
         "tech_keywords": ["mysql"], "waf_vendors": [], "cves": [], "source_ref": "page 1"},
    ])])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    source = library_store.get_source(sid)
    assert source["status"] == "analyzed"
    assert source["ingested_count"] == 1
    store = playbook_store.load_playbook_store()
    entry = next(iter(store.values()))[0]
    assert entry["technique"] == "SQLi comment bypass"
    assert entry["source_type"] == "extracted"
    assert entry["confidence"] == "unreviewed"
    assert entry["source_id"] == sid
    assert entry["source_ref"] == "page 1"


def test_run_analysis_multi_chunk_runs_a_merge_pass(monkeypatch):
    # Long enough to clear _split_into_chunks' own _MIN_CHUNK_CHARS floor even at the smallest
    # possible per-chunk budget, so this is guaranteed to actually split into 2+ chunks.
    text = ("Paragraph about SQLi.\n\n" * 400) + ("Paragraph about XSS.\n\n" * 400)
    sid = library_store.add_source(text.encode(), "book.txt")
    llm = _FakeLLM(context_limit=200, extraction_replies=[
        json.dumps([{"technique": "SQLi technique", "tech_keywords": ["mysql"], "waf_vendors": []}]),
        json.dumps([{"technique": "XSS technique", "tech_keywords": ["react"], "waf_vendors": []}]),
    ])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    source = library_store.get_source(sid)
    assert source["chunks_total"] >= 2
    assert source["status"] == "analyzed"
    assert source["ingested_count"] == 2
    calls_after_extraction = llm.calls
    assert calls_after_extraction == source["chunks_total"] + 1  # +1 for the merge pass


def test_start_analysis_sets_calling_llm_stage_synchronously(monkeypatch):
    # Real, direct operator ask: for the overwhelmingly common single-chunk source, the chunk
    # progress bar alone can only ever show 0% then 100% -- this stage label is real sub-progress
    # within that one chunk's own analysis pass, and must already be set the instant the click is
    # accepted (same synchronous-write discipline as status="analyzing" itself).
    sid = library_store.add_source(b"A paragraph about a technique.", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=["[]"])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    async def _main():
        refusal = library_store.start_analysis(sid, "fake", "fake-model")
        assert refusal == ""
        assert library_store.get_source(sid)["analysis_stage"] == "calling LLM…"
        for task in list(library_store._RUNNING_ANALYSES.values()):
            await task
    _run(_main())


def test_run_analysis_progresses_through_merging_and_saving_stages(monkeypatch):
    text = ("Paragraph about SQLi.\n\n" * 400) + ("Paragraph about XSS.\n\n" * 400)
    sid = library_store.add_source(text.encode(), "book.txt")
    llm = _FakeLLM(context_limit=200, extraction_replies=[
        json.dumps([{"technique": "SQLi technique", "tech_keywords": ["mysql"], "waf_vendors": []}]),
        json.dumps([{"technique": "XSS technique", "tech_keywords": ["react"], "waf_vendors": []}]),
    ])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)
    seen_stages = []
    real_update = library_store._update_source

    def _spy_update(source_id, **fields):
        if "analysis_stage" in fields:
            seen_stages.append(fields["analysis_stage"])
        real_update(source_id, **fields)
    monkeypatch.setattr(library_store, "_update_source", _spy_update)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    assert "calling LLM…" in seen_stages
    assert "merging near-duplicate techniques…" in seen_stages
    assert "saving extracted techniques…" in seen_stages
    assert seen_stages.index("calling LLM…") < seen_stages.index("merging near-duplicate techniques…") < seen_stages.index("saving extracted techniques…")


def test_run_analysis_survives_one_broken_chunk(monkeypatch):
    text = ("Paragraph one.\n\n" * 400) + ("Paragraph two.\n\n" * 400)
    sid = library_store.add_source(text.encode(), "book.txt")
    llm = _FakeLLM(context_limit=200, extraction_replies=[
        "not valid json at all",
        json.dumps([{"technique": "Recovered technique", "tech_keywords": ["php"], "waf_vendors": []}]),
    ])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    source = library_store.get_source(sid)
    assert source["status"] == "analyzed"  # one broken chunk doesn't sink the whole run
    assert source["ingested_count"] == 1


def test_run_analysis_candidate_with_no_tech_keywords_and_no_derivable_ones_is_skipped(monkeypatch):
    sid = library_store.add_source(b"Some vague paragraph.", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=[json.dumps([
        {"technique": "!!!", "tech_keywords": [], "waf_vendors": []},  # no real tech tokens anywhere
    ])])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    assert library_store.get_source(sid)["ingested_count"] == 0
    assert playbook_store.load_playbook_store() == {}


def test_run_analysis_refuses_when_chunk_count_exceeds_the_safety_cap(monkeypatch):
    """Real, confirmed gap this guards: chunk count scales with document size / the chosen
    model's own context window, with no cap of its own -- a big real document against a
    small-context model could otherwise turn into hundreds of sequential LLM calls."""
    monkeypatch.setattr(library_store, "_MAX_CHUNKS", 2)
    text = "Paragraph.\n\n" * 10_000  # comfortably splits into far more than 2 chunks
    sid = library_store.add_source(text.encode(), "book.txt")
    llm = _FakeLLM(context_limit=200, extraction_replies=[])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    source = library_store.get_source(sid)
    assert source["status"] == "error"
    assert "chunk" in source["error"]
    assert llm.calls == 0  # refused before making a single LLM call


def test_run_analysis_unresolvable_provider_marks_source_error(monkeypatch):
    sid = library_store.add_source(b"some text", "t.txt")

    def _boom(provider_id, model):
        raise ValueError("no api key configured")
    monkeypatch.setattr(library_store, "get_provider", _boom)

    _run(library_store._run_analysis(sid, "bad-provider", "bad-model"))

    source = library_store.get_source(sid)
    assert source["status"] == "error"
    assert "provider error" in source["error"]


def test_start_analysis_schedules_a_real_task_and_returns_empty_string(monkeypatch):
    sid = library_store.add_source(b"A paragraph about a technique.", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=["[]"])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    async def _main():
        refusal = library_store.start_analysis(sid, "fake", "fake-model")
        assert refusal == ""
        for task in list(library_store._RUNNING_ANALYSES.values()):
            await task
    _run(_main())

    assert library_store.get_source(sid)["status"] == "analyzed"


def test_start_analysis_status_is_already_analyzing_before_the_call_returns(monkeypatch):
    # Real bug, fixed live: the route handler renders the card in the SAME synchronous call that
    # invokes start_analysis, with no await in between -- if "analyzing" were only written inside
    # the background task's own body (as it used to be), that first render would still show the
    # OLD status and (since library_card.html's self-poll is gated on status=="analyzing") would
    # carry no self-poll either, leaving the card looking untouched until a second click. This
    # pins the fix: the status must already be "analyzing" the instant start_analysis returns,
    # before the scheduled task has had any chance to actually run.
    sid = library_store.add_source(b"A paragraph about a technique.", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=["[]"])
    monkeypatch.setattr(library_store, "get_provider", lambda provider_id, model: llm)

    async def _main():
        refusal = library_store.start_analysis(sid, "fake", "fake-model")
        assert refusal == ""
        source = library_store.get_source(sid)
        assert source["status"] == "analyzing"
        assert source["chunks_total"] == 1
        assert source["chunks_done"] == 0
        for task in list(library_store._RUNNING_ANALYSES.values()):
            await task
    _run(_main())


def test_start_analysis_refuses_a_source_that_doesnt_exist():
    assert library_store.start_analysis("nope", "p", "m") != ""


def test_start_analysis_refuses_beyond_max_concurrent_analyses(monkeypatch):
    monkeypatch.setattr(library_store, "_MAX_CONCURRENT_ANALYSES", 1)
    sid2 = library_store.add_source(b"para two", "b.txt")

    async def _main():
        never_done = asyncio.ensure_future(asyncio.sleep(3600))
        library_store._RUNNING_ANALYSES["other_source"] = never_done
        try:
            refusal = library_store.start_analysis(sid2, "fake", "fake-model")
            assert refusal != ""
            assert "already in progress" in refusal
        finally:
            never_done.cancel()
            library_store._RUNNING_ANALYSES.pop("other_source", None)
    _run(_main())


def test_start_analysis_never_refused_on_concurrency_when_limit_is_zero(monkeypatch):
    monkeypatch.setattr(library_store, "_MAX_CONCURRENT_ANALYSES", 0)
    sid = library_store.add_source(b"content", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=["[]"])
    monkeypatch.setattr(library_store, "get_provider", lambda p, m: llm)
    placeholder_keys = [f"placeholder{i}" for i in range(10)]

    async def _main():
        for key in placeholder_keys:
            library_store._RUNNING_ANALYSES[key] = asyncio.ensure_future(asyncio.sleep(3600))
        try:
            refusal = library_store.start_analysis(sid, "fake", "fake-model")
            assert refusal == ""
            real_task = library_store._RUNNING_ANALYSES.get(sid)
            if real_task is not None:
                await real_task
        finally:
            for key in placeholder_keys:
                task = library_store._RUNNING_ANALYSES.pop(key, None)
                if task is not None:
                    task.cancel()
    _run(_main())


# --- stop_analysis ---


def test_stop_analysis_returns_false_when_nothing_running():
    sid = library_store.add_source(b"content", "t.txt")
    assert library_store.stop_analysis(sid) is False


class _SlowOnSecondCallLLM:
    provider_id = "fake"
    model = "fake-model"
    context_limit = 200

    def __init__(self):
        self.calls = 0

    def complete(self, messages, tools, stop_check=None):
        self.calls += 1
        if messages[-1]["content"].startswith("["):
            return _FakeResponse(messages[-1]["content"])
        if self.calls == 1:
            return _FakeResponse('[{"technique": "T1 from chunk 1", "tech_keywords": ["mysql"], "waf_vendors": []}]')
        # The chunk stop_analysis is expected to interrupt -- a real, blocking (not async) sleep,
        # exactly like the real asyncio.to_thread-wrapped LLM call this stands in for.
        time.sleep(2)
        return _FakeResponse('[{"technique": "T2 from chunk 2 -- should never be reached", "tech_keywords": ["mysql"], "waf_vendors": []}]')

    def embed(self, texts, model):
        return None


def test_stop_analysis_cancels_a_running_task_and_keeps_completed_chunk_results(monkeypatch):
    text = ("Paragraph one.\n\n" * 400) + ("Paragraph two.\n\n" * 400)  # splits into 2+ chunks
    sid = library_store.add_source(text.encode(), "book.txt")
    llm = _SlowOnSecondCallLLM()
    monkeypatch.setattr(library_store, "get_provider", lambda p, m: llm)

    async def _main():
        refusal = library_store.start_analysis(sid, "fake", "fake-model")
        assert refusal == ""
        await asyncio.sleep(0.3)  # let the first (fast) chunk finish, second (slow) chunk start
        assert library_store.get_source(sid)["chunks_done"] == 1
        stopped = library_store.stop_analysis(sid)
        assert stopped is True
        task = library_store._RUNNING_ANALYSES.get(sid)
        if task is not None:
            await task
    _run(_main())

    source = library_store.get_source(sid)
    assert source["status"] == "stopped"
    assert source["ingested_count"] == 1  # kept the first chunk's real, already-extracted result
    assert "Stopped by operator" in source["error"]
    store = playbook_store.load_playbook_store()
    technique = next(iter(store.values()))[0]["technique"]
    assert technique == "T1 from chunk 1"  # only the completed chunk's result, never chunk 2's


def test_stopped_source_can_be_re_analyzed(monkeypatch):
    sid = library_store.add_source(b"content", "t.txt")
    library_store._update_source(sid, status="stopped", error="Stopped by operator after 1/3 chunk(s).")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=["[]"])
    monkeypatch.setattr(library_store, "get_provider", lambda p, m: llm)

    async def _main():
        refusal = library_store.start_analysis(sid, "fake", "fake-model")
        assert refusal != "this source isn't ready to be analyzed right now"
        task = library_store._RUNNING_ANALYSES.get(sid)
        if task is not None:
            await task
    _run(_main())


# --- last-used provider/model persistence ---


def test_load_library_settings_defaults_to_none():
    assert library_store.load_library_settings() == {"last_provider": None, "last_model": None}


def test_save_and_load_last_analysis_llm_roundtrip():
    library_store.save_last_analysis_llm("opencode-zen", "big-pickle")
    assert library_store.load_library_settings() == {"last_provider": "opencode-zen", "last_model": "big-pickle"}


def test_start_analysis_saves_the_provider_and_model_it_was_started_with(monkeypatch):
    sid = library_store.add_source(b"content", "t.txt")
    llm = _FakeLLM(context_limit=100_000, extraction_replies=["[]"])
    monkeypatch.setattr(library_store, "get_provider", lambda p, m: llm)

    async def _main():
        library_store.start_analysis(sid, "myprovider", "mymodel")
    _run(_main())

    assert library_store.load_library_settings() == {"last_provider": "myprovider", "last_model": "mymodel"}


# --- 0 = unlimited convention ---


def test_limit_label_shows_infinity_for_zero_or_negative():
    assert library_store._limit_label(0) == "∞"
    assert library_store._limit_label(-1) == "∞"
    assert library_store._limit_label(5) == "5"


def test_run_analysis_never_refused_on_chunk_count_when_limit_is_zero(monkeypatch):
    monkeypatch.setattr(library_store, "_MAX_CHUNKS", 0)
    text = "Paragraph.\n\n" * 10_000
    sid = library_store.add_source(text.encode(), "book.txt")
    llm = _FakeLLM(context_limit=200, extraction_replies=[])
    monkeypatch.setattr(library_store, "get_provider", lambda p, m: llm)

    _run(library_store._run_analysis(sid, "fake", "fake-model"))

    assert library_store.get_source(sid)["status"] == "analyzed"  # not refused despite many chunks
