"""Knowledge-library source ingestion -- the second feed into the cross-session playbook
(agent/tools/playbook_store.py) alongside real captured findings: an operator uploads a raw
source (PDF/epub/md/txt, often a whole book), ASRA normalizes it to plain text, then an
LLM (the operator's own choice of already-configured provider/model, same picker the Chat panel
already uses) reads it chunk by chunk and extracts candidate techniques -- written into the
playbook as source_type="extracted", confidence="unreviewed", never mixed silently into the same
standing as a field-proven finding (see playbook_store.py's own record_technique docstring for
the automatic-review half of that split; mark_reviewed is the manual half).

Same on-disk convention as playbook_store.py/wordlist_store.py (load/_write pair, atomic
tmp-file + os.replace) -- app-level state that spans every session/project, not tied to one
session_id. Real files (the operator's own uploaded book, unlike anything else this app stores)
live under resolve_global_app_dir(), never this repo's own data/ directory.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.llm_client import get_provider
from agent.prompts import LIBRARY_EXTRACTION_PROMPT, LIBRARY_MERGE_PROMPT
from agent.tools import playbook_store
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("LIBRARY")

_LIBRARY_DIR_NAME = "library"
_SOURCES_SUBDIR = "sources"

_SUPPORTED_FORMATS = {"pdf", "epub", "txt", "md", "html"}

# Fetching an operator-pasted URL is a plain manual reference lookup (the operator chose it and
# typed it in themselves), not the agent choosing to hit a target -- deliberately NOT routed
# through agent/tools/allowed_targets.py's exploitation-scope authorization, same reasoning
# terminal_manager.py's own docstring already gives for why the standalone Terminal isn't gated
# by it either. A plain httpx.Client here, not the agent-tool-shaped http_request (agent/tools/
# native.py) -- that one's params/return shape and target-authorization plumbing exist for a
# completely different caller (a model choosing what to hit), not this one (an operator-supplied
# reference URL to just fetch and read).
_URL_FETCH_TIMEOUT_SECONDS = 30.0
# A generous cap, not a real limit on legitimate reference material -- just enough to refuse an
# operator-pasted link that turns out to be a multi-gigabyte file before it's fully downloaded
# into memory.
_URL_MAX_BYTES = 50 * 1024 * 1024

# Same rough chars-per-token heuristic agent/chat.py's own _estimate_tokens already uses --
# duplicated as a bare constant (not imported) for the same reason terminal_manager.py's own
# _is_wsl_host duplicates a two-line check instead of reaching into another module for it: this
# is cheaper to keep in sync as a literal than to couple two modules over one integer division.
_CHARS_PER_TOKEN = 4

# Conservative floor used only when the selected provider/model's REAL context_limit is unknown
# (models.dev catalog miss, a local model, an unreachable catalog) -- never presented as a claim
# about any specific model, just a safe default so chunking still produces something sane.
_DEFAULT_CONTEXT_LIMIT_TOKENS = 128_000
# Headroom reserved out of the context budget for the system prompt + the model's own JSON
# reply -- the rest is what a chunk of source text is actually allowed to fill.
_PROMPT_RESERVE_FRACTION = 0.25
_MIN_CHUNK_CHARS = 4_000

# A chunk packed to 75% of a big model's whole context window turns a 300-page book into a handful
# of enormous chunks -- one LLM pass per chunk then has to find every technique buried in tens of
# thousands of tokens at once, and recall drops. Capping each chunk to a denser target instead
# splits long sources into many smaller, more focused passes (better recall) while keeping the
# per-source chunk count bounded by _MAX_CHUNKS. The cap only ever lowers the context-derived
# budget, never raises it past what the chosen model can actually hold. Env-overridable;
# 0 = no cap (fall back to the pure context-window budget), same convention as _MAX_CHUNKS below.
_CHUNK_TARGET_TOKENS = int(os.environ.get("LIBRARY_CHUNK_TARGET_TOKENS", "6000"))

# Budget on how many chunks (= sequential LLM calls) ONE analysis run makes. This is NOT a hard
# reject anymore: a source that would exceed the budget is still analyzed, but its chunks are
# EVENLY SAMPLED across the whole document (_cap_chunks_covering) so a long book is covered end to
# end within the budget instead of either (a) being refused outright -- the old behavior, which with
# the denser LIBRARY_CHUNK_TARGET_TOKENS chunking made large sources error out constantly and extract
# nothing -- or (b) only ever reading its first N chunks and never its later chapters. The chunk
# estimate shown before Analyze already lets an operator see the real count and pick a bigger-context
# model; this budget is what keeps "click Analyze on a 1000-page PDF" from turning into an unbounded
# number of real LLM calls, while still learning something from every part of it. Env-overridable;
# 0 = unlimited (no sampling, one call per chunk however many that is) -- shown to the operator as the
# infinity symbol rather than a number that would falsely imply a real ceiling.
_MAX_CHUNKS = int(os.environ.get("LIBRARY_MAX_CHUNKS", "120"))

# Real, confirmed gap this closes: start_analysis had no cap of its own on how many analyses could
# run AT ONCE -- clicking Analyze on every card in the panel fired that many fully independent,
# fully concurrent asyncio.create_task runs, each making its own real sequential LLM calls, with
# nothing coordinating between them (same "no limit at all" question the operator asked directly).
# Same "max_concurrent" shape agent/tools/background_jobs.py's own start_background_job already
# enforces per-session for a different kind of long-running task, applied here per-PROCESS since
# analyses aren't scoped to any one session. 0 = unlimited, same convention as _MAX_CHUNKS above.
_MAX_CONCURRENT_ANALYSES = int(os.environ.get("LIBRARY_MAX_CONCURRENT_ANALYSES", "2"))

_INFINITY = "∞"


def _limit_label(limit: int) -> str:
    """0 reads as the infinity symbol (genuinely unlimited), never as the number 0 -- 0 running
    LLM calls allowed would be a nonsensical thing to actually display."""
    return _INFINITY if limit <= 0 else str(limit)


_JSON_BLOCK_RE = re.compile(r"(\[.*\]|\{.*\})", re.DOTALL)

# Keyed by source_id, not a flat set -- holds references to in-flight analysis tasks so asyncio
# doesn't garbage-collect a task that nothing else awaits directly (the same defensive pattern
# this project already needs anywhere a fire-and-forget asyncio.create_task is the whole point --
# there is no caller left holding it), AND so stop_analysis can actually find and cancel the ONE
# real task behind a specific source's own "Stop" button instead of having no way to address it.
_RUNNING_ANALYSES: dict[str, asyncio.Task] = {}


def _library_dir() -> Path:
    return resolve_global_app_dir() / "data" / _LIBRARY_DIR_NAME


def _sources_path() -> Path:
    return _library_dir() / "sources.json"


def _settings_path() -> Path:
    return _library_dir() / "settings.json"


def load_library_settings() -> dict:
    """Currently just the last provider/model the operator explicitly picked in the panel's own
    shared picker -- a separate small file rather than folding this into sources.json (a flat
    dict of unrelated source records), same "small dedicated settings file" shape
    agent/tools/chat_settings_store.py already uses for the identical last-provider/last-model
    idea in the Chat panel. Real, confirmed operator complaint this fixes: the shared picker
    always reset to blank ("same as main agent") on every page load/reload, so a favorite
    provider/model had to be re-picked every single time instead of being remembered."""
    path = _settings_path()
    _defaults = {"last_provider": None, "last_model": None, "last_free_only": False}
    if not path.exists():
        return dict(_defaults)
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("library: settings.json unreadable (%s) -- treating as unset", exc)
        return dict(_defaults)
    if not isinstance(data, dict):
        return dict(_defaults)
    provider = data.get("last_provider")
    model = data.get("last_model")
    return {
        "last_provider": provider if isinstance(provider, str) and provider else None,
        "last_model": model if isinstance(model, str) and model else None,
        # This picker's own "Free models only" switch state (playbook.html) -- persisted the same
        # way as last_provider/last_model, for the same reason: a toggle remembers its own
        # position, same real, confirmed operator complaint that pair's own docstring describes.
        "last_free_only": bool(data.get("last_free_only")),
    }


def save_last_analysis_llm(provider: str | None, model: str | None, free_only: bool = False) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    settings = {"last_provider": provider or None, "last_model": model or None, "last_free_only": bool(free_only)}
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    tmp_path.replace(path)
    logger.debug(
        "library: saved last_provider=%s last_model=%s last_free_only=%s",
        settings["last_provider"], settings["last_model"], settings["last_free_only"],
    )


def _source_dir(source_id: str) -> Path:
    return _library_dir() / _SOURCES_SUBDIR / source_id


def load_sources() -> dict[str, dict]:
    path = _sources_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("library: sources.json unreadable (%s) -- treating as empty", exc)
        return {}
    return data if isinstance(data, dict) else {}


def _write_sources(data: dict) -> None:
    path = _sources_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp_path.replace(path)


def _update_source(source_id: str, **fields) -> None:
    data = load_sources()
    entry = data.get(source_id)
    if entry is None:
        return
    entry.update(fields)
    _write_sources(data)


def reconcile_orphaned_analyses() -> int:
    """Called once at server startup (main.py's _lifespan, same place sessions/chat threads get
    their own orphan sweep) -- a source can be left with status="analyzing" forever if the server
    process dies or restarts while _run_analysis is mid-flight: that status is only ever written
    FORWARD (normalized -> analyzing -> analyzed/error) by the async task itself, and nothing else
    ever moves it on. _RUNNING_ANALYSES (the in-memory task registry that would normally track
    this) is empty in a freshly-started process regardless of what's on disk, so without this sweep
    a source stuck this way stays stuck across every future restart too -- its own status gates the
    Analyze button and chunk-estimate span OFF entirely (both only render for "normalized"/
    "analyzed"/"error"/"stopped"), so the operator has no way back in through the UI at all, and
    the per-card self-poll (partials/library_card.html) this status also keeps alive polls forever
    for a task that will never resume. Real, confirmed operator complaint this fixes: exactly this
    state, reproduced by clicking
    Analyze then restarting the whole app before it finished. Flips every "analyzing" source to
    "error" with a message that's explicit about WHY (not a generic failure) and that a plain retry
    is exactly what's needed. Returns how many were reconciled."""
    data = load_sources()
    fixed = 0
    for entry in data.values():
        if entry.get("status") == "analyzing":
            entry["status"] = "error"
            entry["error"] = "Interrupted — the server restarted mid-analysis. Click Analyze again."
            fixed += 1
        elif entry.get("status") == "queued":
            # The in-memory queue didn't survive the restart -- flip a stranded "queued" source back
            # to "normalized" (ready to analyze) so it's re-startable, never stuck waiting on a drain
            # that will never come.
            entry["status"] = "normalized"
            entry["error"] = None
            fixed += 1
    if fixed:
        _write_sources(data)
        logger.debug("library: reconciled %d source(s) stuck at status=analyzing from a previous process", fixed)
    else:
        logger.debug("library: startup reconcile -- nothing stuck at status=analyzing")
    return fixed


def get_source(source_id: str) -> dict | None:
    return load_sources().get(source_id)


def list_sources() -> list[dict]:
    """Newest-first, for the library panel's own source list."""
    return sorted(load_sources().values(), key=lambda s: s.get("uploaded_at", ""), reverse=True)


def delete_source(source_id: str) -> bool:
    data = load_sources()
    if source_id not in data:
        return False
    del data[source_id]
    _write_sources(data)
    source_dir = _source_dir(source_id)
    if source_dir.is_dir():
        for child in source_dir.iterdir():
            child.unlink(missing_ok=True)
        source_dir.rmdir()
    logger.debug("library: deleted source id=%s", source_id)
    return True


def _detect_format(filename: str) -> str | None:
    ext = Path(filename).suffix.lstrip(".").lower()
    if ext in _SUPPORTED_FORMATS:
        return ext
    return None


def _normalize_pdf(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    parts: list[str] = []
    for i, page in enumerate(reader.pages):
        try:
            text = (page.extract_text() or "").strip()
        except Exception as exc:
            # A single malformed page shouldn't sink the whole document -- skip it and keep going,
            # same failure-safe spirit as the LLM-extraction chunk loop below.
            logger.debug("library: pdf page %d text extraction failed (%s)", i + 1, exc)
            continue
        if text:
            parts.append(f"[page {i + 1}]\n{text}")
    return "\n\n".join(parts)


def _normalize_epub(data: bytes) -> str:
    from bs4 import BeautifulSoup
    from ebooklib import epub, ITEM_DOCUMENT

    # ebooklib's own read_epub only accepts a real file path, not a file-like object -- the
    # upload is written to a throwaway temp file for the duration of this one parse only.
    with tempfile.NamedTemporaryFile(suffix=".epub", delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        book = epub.read_epub(str(tmp_path))
        parts: list[str] = []
        chapter_num = 0
        for idref, _linear in book.spine:
            item = book.get_item_with_id(idref)
            # spine also carries the nav/TOC document (same ITEM_DOCUMENT type as a real
            # chapter) -- excluded by class, not type, since navigation boilerplate isn't
            # source content worth an LLM extraction pass.
            if item is None or item.get_type() != ITEM_DOCUMENT or isinstance(item, epub.EpubNav):
                continue
            soup = BeautifulSoup(item.get_content(), "html.parser")
            text = soup.get_text("\n", strip=True)
            if text:
                chapter_num += 1
                parts.append(f"[chapter {chapter_num}]\n{text}")
        return "\n\n".join(parts)
    finally:
        tmp_path.unlink(missing_ok=True)


def _normalize_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _normalize_html(data: bytes) -> str:
    """A fetched web page (add_source_from_url's own default format when the URL isn't obviously
    a PDF/epub) -- strips markup down to readable text the same way _normalize_epub already does
    for one HTML document at a time, plus drops <script>/<style>/<nav>/<header>/<footer> content
    first (real page furniture, never the article's own text) so those don't pollute what the LLM
    extraction pass actually reads."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(data, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "noscript"]):
        tag.decompose()
    return soup.get_text("\n", strip=True)


def normalize_source_bytes(fmt: str, data: bytes) -> str:
    if fmt == "pdf":
        return _normalize_pdf(data)
    if fmt == "epub":
        return _normalize_epub(data)
    if fmt == "html":
        return _normalize_html(data)
    return _normalize_text(data)


def _find_duplicate_source(content_hash: str, exclude_id: str | None = None) -> dict | None:
    """The same real material re-uploaded (the exact same PDF under a different filename, the
    exact same article fetched twice) used to just silently create a second, indistinguishable
    source -- a real, direct operator ask: the system should recognize it's the same content and
    ask before doing that again. Matched on a SHA-256 of the raw bytes (content_hash, computed
    once in _create_source), not filename or URL -- both of those collide or diverge for reasons
    that have nothing to do with whether the actual material is identical. Returns the first
    existing source with the same hash (oldest-first iteration order, i.e. the ORIGINAL upload,
    not whichever duplicate got created most recently), or None."""
    for source in load_sources().values():
        if source.get("id") != exclude_id and source.get("content_hash") == content_hash:
            return source
    return None


def _create_source(
    data: bytes, filename: str, fmt: str, title: str, author: str,
    source_url: str | None = None, fetched_via: str | None = None, force: bool = False,
) -> str:
    """Shared by add_source (a real upload) and add_source_from_url (a fetched web page/PDF) --
    stores the raw bytes and writes metadata synchronously; normalization to plain text happens
    immediately too UNLESS this content hash-matches an existing source and force is False, in
    which case it stops at status="duplicate_pending" instead (see _find_duplicate_source) and
    waits for an explicit confirm_duplicate_upload call -- the operator's own choice to upload the
    same material again anyway, not an assumption made on their behalf. Always succeeds at
    creating the source entry, even if normalization itself fails (recorded as status="error", not
    raised to the caller) or a duplicate is found (recorded as status="duplicate_pending", also not
    raised). fetched_via is None for a plain upload or a URL that a plain httpx GET already handled
    fine; "browser" only when add_source_from_url actually had to fall back to real browser
    automation to get usable content -- surfaced in the card (library_card.html) as a small badge,
    since that fallback used to be invisible to the operator anywhere outside debug.log."""
    source_id = uuid.uuid4().hex[:12]
    source_dir = _source_dir(source_id)
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / f"original.{fmt}").write_bytes(data)
    content_hash = hashlib.sha256(data).hexdigest()

    duplicate = None if force else _find_duplicate_source(content_hash)

    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": source_id,
        "filename": filename,
        "format": fmt,
        "title": (title or "").strip() or filename,
        "author": (author or "").strip() or None,
        "source_url": source_url,
        "fetched_via": fetched_via,
        "content_hash": content_hash,
        "status": "duplicate_pending" if duplicate else "normalizing",
        "duplicate_of_id": duplicate.get("id") if duplicate else None,
        "duplicate_of_title": duplicate.get("title") if duplicate else None,
        "error": None,
        "uploaded_at": now,
        "char_count": 0,
        "chunks_total": None,
        "chunks_done": 0,
        # When a source is bigger than the analysis call budget, its chunks are sampled evenly across
        # the whole document; this holds the pre-sampling chunk count so the card can show coverage.
        "coverage_total": None,
        "ingested_count": 0,
        "provider_id": None,
        "model": None,
        "analyzed_at": None,
    }
    sources = load_sources()
    sources[source_id] = entry
    _write_sources(sources)

    if duplicate:
        logger.debug("library: source=%s content-hash matches existing source=%s -- holding at duplicate_pending", source_id, duplicate.get("id"))
        return source_id

    _normalize_and_store(source_id, fmt, data)
    return source_id


def confirm_duplicate_upload(source_id: str) -> bool:
    """The Library panel's own "Add anyway" button on a status="duplicate_pending" card -- the
    operator's explicit choice to proceed with the same material a second time. Moves it into the
    exact same normalize-then-normalized/error flow _create_source's own non-duplicate path already
    uses. Returns False (no-op) if the source doesn't exist or isn't actually duplicate_pending."""
    source = get_source(source_id)
    if source is None or source.get("status") != "duplicate_pending":
        logger.debug("library: confirm_duplicate_upload refused source=%s -- status=%r not duplicate_pending", source_id, source.get("status") if source else None)
        return False
    original_path = _source_dir(source_id) / f"original.{source['format']}"
    data = original_path.read_bytes()
    logger.debug("library: confirm_duplicate_upload source=%s -- proceeding despite matching source=%s", source_id, source.get("duplicate_of_id"))
    _normalize_and_store(source_id, source["format"], data)
    return True


def _normalize_and_store(source_id: str, fmt: str, data: bytes) -> None:
    """The actual normalize-to-plain-text pass, shared by _create_source's own non-duplicate path
    and confirm_duplicate_upload's "proceed anyway" path -- writes status="normalizing" first
    (visible immediately on a duplicate-confirm's own response, same reasoning as
    _prepare_analysis's own synchronous status write elsewhere in this file), then normalizes."""
    _update_source(source_id, status="normalizing")
    source_dir = _source_dir(source_id)
    try:
        text = normalize_source_bytes(fmt, data)
    except Exception as exc:
        logger.debug("library: normalization failed source=%s (%s)", source_id, exc)
        _update_source(source_id, status="error", error=f"normalization failed: {exc}")
        return

    (source_dir / "source.txt").write_text(text, encoding="utf-8")
    if text.strip():
        _update_source(source_id, status="normalized", char_count=len(text))
        logger.debug("library: added+normalized source id=%s format=%s chars=%d", source_id, fmt, len(text))
    else:
        _update_source(source_id, status="error", error="no extractable text found in this source")


def add_source(file_bytes: bytes, filename: str, title: str = "", author: str = "") -> str | None:
    """A real upload -- format is taken from the filename's own extension. Returns the new
    source_id, or None if that extension isn't one of the supported formats."""
    fmt = _detect_format(filename)
    if fmt is None:
        logger.debug("library: upload rejected filename=%r -- unsupported extension", filename)
        return None
    return _create_source(file_bytes, filename, fmt, title, author)


def _detect_format_from_response(url: str, content_type: str) -> str:
    content_type = (content_type or "").split(";")[0].strip().lower()
    if content_type == "application/pdf" or url.lower().endswith(".pdf"):
        return "pdf"
    if content_type in ("application/epub+zip",) or url.lower().endswith(".epub"):
        return "epub"
    if url.lower().endswith(".md"):
        return "md"
    if url.lower().endswith(".txt"):
        return "txt"
    # Anything else (text/html, or a content-type-less response) is read as a web page --
    # the safe, general-purpose default for "the operator pasted a link to an article/writeup".
    return "html"


# A real browser's own request headers. httpx's default User-Agent is "python-httpx/x.y", which a
# great many news/security sites bot-block with an instant 403 (confirmed live: informat.ro returned
# 403 to the bare client but 200 the moment a browser UA + Accept headers were sent -- the same for
# many Cloudflare/Akamai-fronted article sites). Sending a plausible browser fingerprint lets the
# cheap httpx path succeed on everything except sites that additionally run a JS challenge, which
# fall through to the real-browser fallback below.
_BROWSER_LIKE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _fetch_via_httpx(url: str) -> tuple[bytes, str] | None:
    """Plain HTTP GET -- the fast, cheap path that covers the overwhelming majority of real
    articles/writeups/PDFs. Sends browser-like headers (_BROWSER_LIKE_HEADERS) so a UA-filtering
    site doesn't 403 the bare python-httpx client. Returns (data, content_type), or None on any
    failure (bad status, connection error, exceeding _URL_MAX_BYTES)."""
    import httpx

    try:
        with httpx.Client(timeout=_URL_FETCH_TIMEOUT_SECONDS, follow_redirects=True, headers=_BROWSER_LIKE_HEADERS) as client:
            with client.stream("GET", url) as resp:
                resp.raise_for_status()
                content_type = resp.headers.get("content-type", "")
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > _URL_MAX_BYTES:
                        logger.debug("library: url fetch aborted, exceeded %d bytes url=%r", _URL_MAX_BYTES, url)
                        return None
                    chunks.append(chunk)
                return b"".join(chunks), content_type
    except (httpx.HTTPError, OSError) as exc:
        logger.debug("library: httpx fetch failed url=%r (%s)", url, exc)
        return None


# Below this many characters of extracted text, a successful httpx fetch of an "html"-shaped
# response is treated as suspicious -- not a real, short page, but almost always a JS-rendered
# single-page app's near-empty server-side shell (the real content only exists after client-side
# JS runs, which a plain GET never executes at all). Low enough that a genuinely short real page
# never gets needlessly re-fetched through the much heavier browser path below.
_MIN_HTML_CHARS_BEFORE_BROWSER_FALLBACK = 200


def _fetch_via_browser(url: str) -> bytes | None:
    """Fallback for exactly the case a plain GET can't handle: a JS-rendered page (nothing real in
    the initial HTML until client-side JS runs) or a site that blocks/challenges non-browser
    requests. Launches its OWN isolated, short-lived headless Chromium via Playwright and tears it
    fully down within this one call.

    Deliberately NOT the shared browser_manager singleton (agent/tools/browser_manager.py), which the
    live agent also uses: Playwright objects are bound to the event loop they were created on, and
    add_source_from_url runs in a worker thread with no loop of its own, so this uses asyncio.run()
    -- a fresh loop per call that closes when it returns. Routing the shared singleton through those
    throwaway loops left it bound to an already-closed loop after the first browser-fallback URL, so
    every later URL that needed the browser hung or errored AND the agent's own shared browser could
    be corrupted mid-session (confirmed operator report: 'after some links the engine dies'). A
    self-contained browser per call has no shared state to corrupt and no cross-loop binding to
    break. Returns the fully-rendered page's own HTML, or None on any failure."""
    async def _run() -> bytes | None:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                    )
                )
                page = await context.new_page()
                try:
                    await page.goto(url, wait_until="networkidle", timeout=_URL_FETCH_TIMEOUT_SECONDS * 1000)
                except Exception as nav_exc:
                    # networkidle can time out on a page that keeps a long-poll/socket open even
                    # though the real content already rendered -- fall back to whatever's loaded.
                    logger.debug("library: browser fallback networkidle wait failed url=%r (%s) -- reading current content", url, nav_exc)
                html = await page.content()
                if not isinstance(html, str) or not html.strip():
                    return None
                return html.encode("utf-8")
            finally:
                await browser.close()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.debug("library: browser fallback fetch failed url=%r (%s)", url, exc)
        return None


def add_source_from_url(url: str, title: str = "", author: str = "") -> str | None:
    """Fetches an operator-pasted URL (an article, writeup, or a direct PDF/epub link) and adds it
    the same way a real upload would be -- a plain manual reference lookup, not something routed
    through agent/tools/allowed_targets.py's exploitation-scope authorization (see this module's
    own _URL_FETCH_TIMEOUT_SECONDS comment for why). Tries a plain HTTP fetch first (_fetch_via_httpx,
    fast and cheap); if that fails outright, or succeeds but the extracted text looks like an empty
    JS-rendered shell, falls back to a real rendered browser fetch (_fetch_via_browser) before
    giving up. Returns the new source_id, or None if the URL itself is malformed/unsupported or
    BOTH fetch paths fail (a source that WAS created but then failed to normalize still gets a
    source_id, same as add_source -- only a fetch failure that never got any bytes at all, from
    either path, returns None, since there's nothing to show the operator yet)."""
    url = (url or "").strip()
    if not url or not url.lower().startswith(("http://", "https://")):
        logger.debug("library: url fetch rejected url=%r -- not an http(s) url", url)
        return None

    via = "httpx"
    fetched = _fetch_via_httpx(url)
    if fetched is not None:
        data, content_type = fetched
        fmt = _detect_format_from_response(url, content_type)
        # Only html-shaped responses can be a JS-rendered empty shell in the first place -- a
        # successfully fetched PDF/epub/txt/md is never "thin because JS hasn't run yet".
        if fmt == "html" and len(_normalize_html(data).strip()) < _MIN_HTML_CHARS_BEFORE_BROWSER_FALLBACK:
            logger.debug("library: httpx result for url=%r looks like a thin/empty shell -- trying browser fallback", url)
            rendered = _fetch_via_browser(url)
            if rendered is not None:
                data = rendered
                via = "browser (httpx result was thin)"
    else:
        logger.debug("library: httpx fetch failed for url=%r -- trying browser fallback", url)
        rendered = _fetch_via_browser(url)
        if rendered is None:
            logger.debug("library: url fetch gave up url=%r -- both httpx and browser fallback failed", url)
            return None
        data, fmt = rendered, "html"
        via = "browser (httpx failed outright)"

    filename = Path(url.split("?")[0].rstrip("/")).name or "webpage"
    if not filename.lower().endswith(f".{fmt}"):
        filename = f"{filename}.{fmt}"
    logger.debug("library: url fetch succeeded url=%r via=%s format=%s bytes=%d", url, via, fmt, len(data))
    fetched_via = "browser" if via.startswith("browser") else None
    return _create_source(data, filename, fmt, title, author, source_url=url, fetched_via=fetched_via)


def _chunk_char_budget(context_limit: int | None) -> int:
    limit_tokens = context_limit or _DEFAULT_CONTEXT_LIMIT_TOKENS
    usable_tokens = int(limit_tokens * (1 - _PROMPT_RESERVE_FRACTION))
    # Cap the context-derived budget to a denser per-chunk target so a long document splits into
    # many focused passes instead of a few huge ones -- never raised above what the model can hold.
    if _CHUNK_TARGET_TOKENS > 0:
        usable_tokens = min(usable_tokens, _CHUNK_TARGET_TOKENS)
    return max(_MIN_CHUNK_CHARS, usable_tokens * _CHARS_PER_TOKEN)


def _split_into_chunks(text: str, chunk_chars: int) -> list[str]:
    """Packs paragraphs into chunks up to chunk_chars, never splitting a paragraph across a
    boundary except for the rare single paragraph that's already bigger than the whole budget (a
    wall of text with no blank lines -- hard-split there so it can't produce one unbounded
    chunk). Each new chunk after the first carries its predecessor's last paragraph forward too
    -- a light overlap so a technique explained right at the seam still reads whole at least once."""
    paragraphs = [p for p in re.split(r"\n{2,}", text) if p.strip()]
    if not paragraphs:
        return []
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for para in paragraphs:
        if len(para) > chunk_chars:
            if current:
                chunks.append("\n\n".join(current))
                current, current_len = [], 0
            for i in range(0, len(para), chunk_chars):
                chunks.append(para[i:i + chunk_chars])
            continue
        if current and current_len + len(para) + 2 > chunk_chars:
            chunks.append("\n\n".join(current))
            current, current_len = [current[-1]], len(current[-1])
        current.append(para)
        current_len += len(para) + 2
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def _cap_chunks_covering(chunks: list[str]) -> list[str]:
    """Bounds an analysis to _MAX_CHUNKS LLM calls while still covering the WHOLE document. When a
    source splits into more chunks than the budget, this evenly samples _MAX_CHUNKS of them spanning
    the full text (first and last always included) rather than taking only the first N -- so a long
    book's later chapters get learned from too, not just its opening. Under the budget (the common
    case) the chunks are returned unchanged. _MAX_CHUNKS <= 0 disables the budget (no sampling)."""
    total = len(chunks)
    if _MAX_CHUNKS <= 0 or total <= _MAX_CHUNKS:
        return chunks
    n = _MAX_CHUNKS
    if n == 1:
        return [chunks[0]]
    # Evenly spaced indices across [0, total-1], both ends inclusive; dedup keeps it <= n.
    idxs = sorted({round(i * (total - 1) / (n - 1)) for i in range(n)})
    return [chunks[i] for i in idxs]


def estimate_chunk_count(source_id: str, provider_id: str, model: str) -> int:
    """How many LLM calls a real analysis run would make -- shown to the operator BEFORE they
    click Analyze, so a 100+ page book never turns into a surprise number of calls."""
    source = get_source(source_id)
    if source is None:
        return 0
    text_path = _source_dir(source_id) / "source.txt"
    if not text_path.is_file():
        return 0
    try:
        context_limit = get_provider(provider_id, model).context_limit
    except Exception as exc:
        logger.debug("library: estimate_chunk_count couldn't resolve provider=%s model=%s (%s) -- using default budget", provider_id, model, exc)
        context_limit = None
    text = text_path.read_text(encoding="utf-8", errors="replace")
    # The RAW chunk count (before the coverage budget). The route decides how to present it: when it
    # exceeds the budget the source isn't refused, it's sampled to cover the whole document within
    # the budget's number of LLM calls -- the route shows that instead of an "over the limit" warning.
    count = len(_split_into_chunks(text, _chunk_char_budget(context_limit)))
    logger.debug("library: estimate_chunk_count source=%s provider=%s model=%s context_limit=%s -> %d chunks (budget %s)", source_id, provider_id, model, context_limit, count, _limit_label(_MAX_CHUNKS))
    return count


def _parse_json_loose(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def _candidate_has_substance(candidate: dict) -> bool:
    """Drops pure theory an extraction pass still returned with a technique name but nothing to act
    on (a chapter intro, a "WAFs can be bypassed" aside). A candidate earns ingestion only if it
    carries something concrete: a real payload/command, an ordered recipe, a transcribed skill body,
    a named CVE, OR a concrete vuln_class paired with a tech stack (enough to retrieve and reason
    about even without a literal payload). Everything else is reading-material prose, not a
    playbook-worthy technique."""
    if str(candidate.get("payload_or_command") or "").strip():
        return True
    recipe = candidate.get("recipe")
    if isinstance(recipe, list) and any(str(step).strip() for step in recipe):
        return True
    skill = candidate.get("skill")
    if isinstance(skill, dict) and str(skill.get("body") or "").strip():
        return True
    if any(str(cve).strip() for cve in (candidate.get("cves") or [])):
        return True
    vuln_class = str(candidate.get("vuln_class") or "").strip()
    tech_keywords = [str(t).strip() for t in (candidate.get("tech_keywords") or []) if str(t).strip()]
    return bool(vuln_class and tech_keywords)


async def _extract_from_chunk(llm, chunk: str) -> list[dict]:
    try:
        response = await asyncio.to_thread(
            llm.complete,
            [
                {"role": "system", "content": LIBRARY_EXTRACTION_PROMPT},
                {"role": "user", "content": chunk},
            ],
            None,
        )
    except Exception as exc:
        logger.debug("library: chunk extraction call failed (%s) -- chunk skipped", exc)
        return []
    parsed = _parse_json_loose(response.content)
    if not isinstance(parsed, list):
        return []
    return [
        e for e in parsed
        if isinstance(e, dict) and str(e.get("technique") or "").strip() and _candidate_has_substance(e)
    ]


# A whole book's worth of candidates in one merge prompt blows the model's context the same way an
# uncapped chunk does -- batch the merge pass so each call sees a bounded slice. Cross-batch
# duplicates survive (a technique in batch 1 and batch 3 won't be collapsed), an acceptable cost:
# the merge pass is a best-effort tidy, not a correctness guarantee, and _MERGE_BATCH_SIZE is large
# enough that a realistic source stays one batch and behaves exactly as the old single pass did.
_MERGE_BATCH_SIZE = int(os.environ.get("LIBRARY_MERGE_BATCH_SIZE", "40"))


async def _merge_batch(llm, candidates: list[dict]) -> list[dict]:
    """One merge LLM pass over a bounded slice of candidates -- best-effort: any failure leaves this
    slice un-merged, same failure-safe shape as agent/core.py's own _run_playbook_distillation_pass."""
    try:
        response = await asyncio.to_thread(
            llm.complete,
            [
                {"role": "system", "content": LIBRARY_MERGE_PROMPT},
                {"role": "user", "content": json.dumps(candidates, ensure_ascii=False)},
            ],
            None,
        )
    except Exception as exc:
        logger.debug("library: merge pass failed (%s) -- keeping un-merged candidates", exc)
        return candidates
    parsed = _parse_json_loose(response.content)
    if not isinstance(parsed, list) or not parsed:
        return candidates
    merged = [e for e in parsed if isinstance(e, dict) and str(e.get("technique") or "").strip()]
    return merged or candidates


async def _merge_candidates(llm, candidates: list[dict]) -> list[dict]:
    """Collapses near-duplicate candidates from the SAME source (the same technique explained once,
    then referenced again later in the book). Chunked into bounded batches so a large book doesn't
    hand the model one giant merge prompt -- for any realistic source (<= _MERGE_BATCH_SIZE
    candidates) this is exactly one pass, identical to the original single-pass behavior."""
    if _MERGE_BATCH_SIZE <= 0 or len(candidates) <= _MERGE_BATCH_SIZE:
        return await _merge_batch(llm, candidates)
    merged: list[dict] = []
    for start in range(0, len(candidates), _MERGE_BATCH_SIZE):
        merged.extend(await _merge_batch(llm, candidates[start:start + _MERGE_BATCH_SIZE]))
    logger.debug("library: merge pass batched %d candidate(s) into %d batch(es)", len(candidates), -(-len(candidates) // _MERGE_BATCH_SIZE))
    return merged


# The target shapes / modes the extraction prompt is allowed to classify a technique into -- a
# whitelist so a stray free-text value the model invents doesn't pollute the store's own cross-mode
# shape matching (playbook_store.find_similar_techniques reads these). Mirrors the enum spelled out
# in LIBRARY_EXTRACTION_PROMPT; anything else normalizes to None (unclassified).
_VALID_TARGET_SHAPES = frozenset({"web", "pe_x86_64", "elf", "jvm_bytecode", "apk", "reverse", "agentic"})
_VALID_MODES = frozenset({"web", "reverse", "interactive", "agentic"})


def _normalize_enum(value, allowed: frozenset) -> str | None:
    token = str(value or "").strip().lower()
    return token if token in allowed else None


def _skill_from_candidate(candidate: dict, target_shape: str | None, mode: str | None) -> dict | None:
    """Builds a normalized, UNTRUSTED skill from a candidate's `skill` sub-object -- but ONLY when
    the extraction pass actually classified a kind+interpreter and transcribed a concrete body. The
    body is the document author's text, not this agent's, so it goes in via build_skill(derived_from=
    "library") which forces trust="unreviewed" and pins the hash; execution stays sandbox-gated
    elsewhere. Pure-prose chunks carry skill=null and get nothing attached. Returns the skill dict,
    or None when there's no well-formed concrete skill to capture."""
    raw = candidate.get("skill")
    if not isinstance(raw, dict):
        return None
    kind = str(raw.get("kind") or "").strip().lower()
    interpreter = str(raw.get("interpreter") or "none").strip().lower()
    body = str(raw.get("body") or "").strip()
    if not kind or not body:
        return None
    return playbook_store.build_skill(
        kind=kind, body=body, params=raw.get("params"), interpreter=interpreter,
        target_shape=target_shape, mode=mode, derived_from="library",
    )


def _ingest_candidate(source: dict, candidate: dict) -> bool:
    """Deterministic write of one extracted candidate into the playbook -- the ONLY thing that
    ever touches the real store on this path, never the LLM directly. Mirrors the entry shape
    every other capture path (agent/core.py, agent/chat.py) already builds, but stamped
    source_type="extracted"/confidence="unreviewed" instead of "live"/"confirmed". When the
    candidate also carries a concrete, transcribed skill, that skill is attached to the recorded
    technique as untrusted/unreviewed material (see _skill_from_candidate)."""
    from agent.core import _technology_keywords  # same private cross-module reuse agent/chat.py already does for this exact helper

    technique = str(candidate.get("technique") or "").strip()
    if not technique:
        return False
    raw_keywords = candidate.get("tech_keywords") or []
    tech_keywords = {str(t).strip().lower() for t in raw_keywords if str(t).strip()}
    if not tech_keywords:
        # No explicit stack given -- fall back to whatever tech tokens the technique text itself
        # carries, same fallback agent/chat.py's own record_technique tool applies.
        tech_keywords = set(_technology_keywords(technique))
    if not tech_keywords:
        logger.debug("library: skipped candidate with no derivable tech_keywords technique=%r", technique[:80])
        return False
    waf_vendors = {str(w).strip().lower() for w in (candidate.get("waf_vendors") or []) if str(w).strip()}
    payload = str(candidate.get("payload_or_command") or "").strip() or None
    target_shape = _normalize_enum(candidate.get("target_shape"), _VALID_TARGET_SHAPES)
    mode = _normalize_enum(candidate.get("mode"), _VALID_MODES)
    now = datetime.now(timezone.utc).isoformat()
    source_ref = candidate.get("source_ref")
    entry = {
        "id": uuid.uuid4().hex[:12],
        "technique": technique,
        "vuln_class": (str(candidate.get("vuln_class") or "").strip() or None),
        "payload_or_command": payload,
        "cves": playbook_store.extract_cves(technique, payload or "", " ".join(str(c) for c in (candidate.get("cves") or []))),
        "evidence_ref": "",
        "tech_keywords": sorted(tech_keywords),
        "waf_vendors": sorted(waf_vendors),
        # Cross-mode shape matching (playbook_store.find_similar_techniques) can only fire when the
        # entry actually carries where it applies -- a reverse/agentic technique whose tech tokens
        # are thin is otherwise invisible to a differently-shaped query.
        "target_shape": target_shape,
        "mode": mode,
        # What the source presents as working -- "failed"/dead-end knowledge isn't really what a
        # book teaches, and this is unreviewed either way until a human or a real field use says so.
        "outcome": "worked",
        "times_confirmed": 1,
        "injected_count": 0,
        "led_to_finding_count": 0,
        "chained_from_ids": [],
        "last_seen": now,
        # Never actually confirmed working yet -- that's the whole point of "unreviewed".
        "last_confirmed_at": None,
        "source_session_ids": [],
        "source_type": "extracted",
        "confidence": "unreviewed",
        "source_id": source.get("id"),
        "source_title": source.get("title") or source.get("filename"),
        "source_author": source.get("author"),
        "source_ref": (str(source_ref).strip() or None) if source_ref else None,
    }
    key = playbook_store.make_fingerprint_key(tech_keywords, waf_vendors)
    recorded_id = playbook_store.record_technique(key, entry)
    if not recorded_id:
        return False

    skill = _skill_from_candidate(candidate, target_shape, mode)
    if skill is not None:
        if playbook_store.attach_skill(recorded_id, skill):
            logger.debug("library: attached %s skill to extracted technique id=%s", skill.get("kind"), recorded_id)
        else:
            logger.debug("library: skill build/attach skipped for technique id=%s (no target entry)", recorded_id)
    return True


def _prepare_analysis(source_id: str, provider_id: str, model: str) -> tuple[Any, list[str]] | None:
    """Synchronous on purpose -- provider resolution and chunking never actually need to await
    anything, so doing this work (and writing status="analyzing" as its LAST step) before
    start_analysis() ever hands control back to the route handler is what makes the very first
    Analyze click's own HTTP response already show "Analyzing..." with a self-poll attached. This
    used to be the first half of an async _run_analysis, run only after asyncio.create_task had
    merely SCHEDULED it -- the route handler's own render (no await between creating the task and
    rendering) always ran first, so the first click's response reflected the OLD, pre-analysis
    status and (since library_card.html only attaches its self-poll when status=="analyzing")
    carried no self-poll either, leaving the card looking untouched until a second click's own
    response finally caught the by-then-real "analyzing" status. Confirmed live via debug.log: a
    "start_analysis accepted" line followed ~3.6s later by a second "refused ... already
    analyzing" line for the SAME source, twice in a row for two different sources -- the operator
    re-clicking because the first click's own response never showed anything had changed.
    Returns (llm, chunks) on success, or None after writing an "error" status directly (treated as
    "accepted the click, but the attempt itself failed" rather than a refusal -- same as before)."""
    source = get_source(source_id)
    if source is None:
        logger.debug("library: analysis aborted -- source=%s no longer exists", source_id)
        return None
    text_path = _source_dir(source_id) / "source.txt"
    if not text_path.is_file():
        _update_source(source_id, status="error", error="normalized text is missing")
        logger.debug("library: analysis aborted source=%s -- normalized text missing", source_id)
        return None

    try:
        llm = get_provider(provider_id, model)
    except Exception as exc:
        logger.debug("library: analysis couldn't resolve provider=%s model=%s (%s)", provider_id, model, exc)
        _update_source(source_id, status="error", error=f"provider error: {exc}")
        return None

    text = text_path.read_text(encoding="utf-8", errors="replace")
    chunks = _split_into_chunks(text, _chunk_char_budget(llm.context_limit))
    if not chunks:
        _update_source(source_id, status="error", error="nothing to analyze")
        logger.debug("library: analysis aborted source=%s -- nothing to analyze", source_id)
        return None
    raw_count = len(chunks)
    chunks = _cap_chunks_covering(chunks)
    coverage_total = raw_count if len(chunks) < raw_count else None
    if coverage_total is not None:
        logger.debug("library: source=%s split into %d chunks -- covering %d evenly across the whole document (budget %d)", source_id, raw_count, len(chunks), _MAX_CHUNKS)

    _update_source(
        source_id, status="analyzing", chunks_total=len(chunks), chunks_done=0,
        # When the source was bigger than the call budget, this is the pre-sampling chunk count so the
        # card can show "covering N of M sections"; None when every chunk is analyzed.
        coverage_total=coverage_total,
        provider_id=provider_id, model=model, error=None,
        # Real, direct operator ask: the chunk progress bar alone can only ever show 0% then 100%
        # for the overwhelmingly common case (a single-chunk source -- see _chunk_char_budget's
        # own math, a whole real article easily fits in one chunk against any modern context
        # window) since there's no intermediate unit of work to report between them. This stage
        # label is real, separate progress WITHIN one chunk's own analysis pass -- see
        # _run_analysis_chunks for where each value actually gets set.
        analysis_stage="calling LLM…",
    )
    logger.debug(
        "library: analysis started source=%s provider=%s model=%s chunks=%d/%s",
        source_id, provider_id, model, len(chunks), _limit_label(_MAX_CHUNKS),
    )
    return llm, chunks


async def _run_analysis(source_id: str, provider_id: str, model: str) -> None:
    """Convenience wrapper kept for direct-call use (tests, anything that wants the full
    prepare+run pipeline in one coroutine) -- start_analysis itself calls _prepare_analysis
    synchronously on its own instead of going through this, so the "analyzing" status is already
    written before start_analysis returns. See _prepare_analysis's own docstring for why."""
    prepared = _prepare_analysis(source_id, provider_id, model)
    if prepared is None:
        return
    llm, chunks = prepared
    await _run_analysis_chunks(source_id, llm, chunks)


async def _refresh_threat_intel_after_ingest(source_id: str, ingested: int) -> None:
    """Freshly-extracted techniques may name CVEs the store has never enriched -- stamp KEV/EPSS/
    PoC signals onto them so scoring and the UI can read them without a network hop later. Runs only
    when something was actually ingested, off the event loop, and fully wrapped: the threat-intel
    endpoints being slow or down never fails (nor delays the terminal status of) the analysis."""
    if not ingested:
        return
    try:
        updated = await asyncio.to_thread(playbook_store.refresh_threat_intel)
        logger.debug("library: threat-intel refresh after source=%s stamped %d technique(s)", source_id, updated)
    except Exception as exc:
        logger.debug("library: threat-intel refresh after source=%s failed (%s) -- extraction still saved", source_id, exc)


async def _run_analysis_chunks(source_id: str, llm: Any, chunks: list[str]) -> None:
    source = get_source(source_id)
    if source is None:
        logger.debug("library: analysis aborted -- source=%s no longer exists", source_id)
        return

    # Cancellation (stop_analysis, via task.cancel()) is NOT instant: asyncio.to_thread wraps a
    # genuinely blocking thread-pool call (the real LLM request) that Python cannot force-kill, so
    # CancelledError only actually reaches this coroutine once the CURRENT chunk's own call
    # returns -- Stop lands after the in-flight chunk finishes, not mid-request. Whatever
    # candidates were already extracted from chunks that DID complete are real, already-paid-for
    # LLM work -- kept and ingested below rather than thrown away just because the operator
    # stopped before the LAST chunk.
    candidates: list[dict] = []
    stopped_early = False
    try:
        for i, chunk in enumerate(chunks):
            _update_source(source_id, analysis_stage="calling LLM…", chunks_done=i)
            candidates.extend(await _extract_from_chunk(llm, chunk))
            _update_source(source_id, chunks_done=i + 1)

        if len(chunks) > 1 and len(candidates) > 1:
            _update_source(source_id, analysis_stage="merging near-duplicate techniques…")
            candidates = await _merge_candidates(llm, candidates)
    except asyncio.CancelledError:
        stopped_early = True
        done = (get_source(source_id) or {}).get("chunks_done", 0)
        logger.debug(
            "library: analysis stopped by operator source=%s after %d/%d chunk(s), %d raw candidate(s) collected so far",
            source_id, done, len(chunks), len(candidates),
        )

    _update_source(source_id, analysis_stage="saving extracted techniques…")
    ingested = sum(1 for c in candidates if _ingest_candidate(source, c))

    if ingested:
        embed = getattr(llm, "embed", None)
        if embed is not None:
            # Best-effort semantic-search indexing for the freshly written entries, same
            # non-fatal spirit as agent/core.py's own _embed_playbook_entries call sites --
            # this never blocks the analysis result on the embeddings endpoint being reachable.
            try:
                from agent.core import _embed_playbook_entries
                fresh = [
                    e for entries in playbook_store.load_playbook_store().values() for e in entries
                    if e.get("source_id") == source_id
                ]
                await asyncio.to_thread(_embed_playbook_entries, llm, fresh)
            except Exception as exc:
                logger.debug("library: embedding pass failed for source=%s (%s) -- keyword search still works", source_id, exc)

    if stopped_early:
        done = (get_source(source_id) or {}).get("chunks_done", 0)
        _update_source(
            source_id, status="stopped", ingested_count=ingested,
            error=f"Stopped by operator after {done}/{len(chunks)} chunk(s) — {ingested} technique(s) already extracted were kept. Click Analyze to run it again from the start.",
        )
        logger.debug("library: analysis stopped source=%s ingested=%d/%d candidate(s) before stopping", source_id, ingested, len(candidates))
        await _refresh_threat_intel_after_ingest(source_id, ingested)
        return

    _update_source(
        source_id, status="analyzed", ingested_count=ingested,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )
    logger.debug("library: analysis finished source=%s ingested=%d/%d candidate(s)", source_id, ingested, len(candidates))
    # Done AFTER the terminal status is written so the "analyzed -- N extracted" card the operator is
    # polling for never waits on a (possibly slow, possibly offline) threat-intel refresh.
    await _refresh_threat_intel_after_ingest(source_id, ingested)


def start_analysis(source_id: str, provider_id: str, model: str, free_only: bool = False) -> str:
    """Fires the (possibly many-minute, many-LLM-call) analysis off as a background asyncio task
    and returns immediately -- the library panel polls get_source(source_id)'s own
    status/chunks_done/chunks_total fields for progress. Like every other in-memory async task in
    this project (e.g. terminal_manager's own PTY sessions), the task itself does not survive a
    server restart -- but reconcile_orphaned_analyses (called once at startup) is what actually
    makes a source left "analyzing" across a restart re-runnable again, not this function; without
    it that source's own status blocks the Analyze button from ever rendering again at all (see
    that function's own docstring for the real incident this fixes).

    Returns "" on success (started OR queued), or a short human-readable reason only when the source
    genuinely isn't analyzable (wrong status). The concurrency budget (_MAX_CONCURRENT_ANALYSES) is
    NOT an error anymore: when every slot is busy the source is QUEUED and started automatically the
    moment a slot frees (_drain_analysis_queue), so an artificial limit degrades gracefully instead
    of stalling the operator with a refusal -- the same principle as the chunk budget, which samples
    to cover a big document rather than refusing it."""
    source = get_source(source_id)
    if source is None or source.get("status") not in ("normalized", "analyzed", "error", "stopped"):
        logger.debug("library: start_analysis refused source=%s -- status=%r not analyzable", source_id, source.get("status") if source else None)
        return "this source isn't ready to be analyzed right now"

    save_last_analysis_llm(provider_id, model, free_only)
    running = count_running_analyses()
    if _MAX_CONCURRENT_ANALYSES > 0 and running >= _MAX_CONCURRENT_ANALYSES:
        _update_source(
            source_id, status="queued", error=None,
            queued_provider_id=provider_id, queued_model=model,
            queued_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.debug("library: queued source=%s -- %d/%d slots busy, will start when one frees", source_id, running, _MAX_CONCURRENT_ANALYSES)
        return ""

    _start_prepared_analysis(source_id, provider_id, model)
    logger.debug("library: start_analysis accepted source=%s provider=%s model=%s (%d/%s running)", source_id, provider_id, model, running + 1, _limit_label(_MAX_CONCURRENT_ANALYSES))
    return ""


def _start_prepared_analysis(source_id: str, provider_id: str, model: str) -> bool:
    """Prepares (synchronously, status -> analyzing) and fires the background analysis task for one
    source. Shared by start_analysis and the queue drain. Returns False if preparation failed (which
    already recorded an error status on the source), True once the task is running. The done-callback
    both frees the in-memory slot AND drains the queue, so a finished analysis pulls the next queued
    one in with no operator action."""
    prepared = _prepare_analysis(source_id, provider_id, model)
    if prepared is None:
        return False
    llm, chunks = prepared
    task = asyncio.create_task(_run_analysis_chunks(source_id, llm, chunks))
    _RUNNING_ANALYSES[source_id] = task

    def _done(_task, sid=source_id):
        _RUNNING_ANALYSES.pop(sid, None)
        try:
            _drain_analysis_queue()
        except Exception as exc:  # a drain failure must never break the finished task's cleanup
            logger.debug("library: queue drain after source=%s failed (%s)", sid, exc)

    task.add_done_callback(_done)
    return True


def _drain_analysis_queue() -> None:
    """Starts queued analyses (oldest first) while a concurrency slot is free. Called whenever a
    running analysis finishes; safe to call anytime. Each queued source carries the provider/model it
    was queued with. A source that can't actually start (its prepare fails) is moved off 'queued' by
    _prepare_analysis's own error write, so this loop can never spin on it."""
    while _MAX_CONCURRENT_ANALYSES <= 0 or count_running_analyses() < _MAX_CONCURRENT_ANALYSES:
        data = load_sources()
        queued = sorted(
            ((sid, e) for sid, e in data.items() if e.get("status") == "queued"),
            key=lambda kv: kv[1].get("queued_at") or "",
        )
        if not queued:
            return
        sid, entry = queued[0]
        provider_id = entry.get("queued_provider_id") or entry.get("provider_id")
        model = entry.get("queued_model") or entry.get("model")
        if not provider_id or not model:
            _update_source(sid, status="error", error="queued analysis lost its provider/model — click Analyze again")
            continue
        logger.debug("library: draining queue -- starting source=%s", sid)
        if not _start_prepared_analysis(sid, provider_id, model) and (get_source(sid) or {}).get("status") == "queued":
            # prepare returned False without recording an error (shouldn't happen) -- fail safe so the
            # loop can't pick this same source forever.
            _update_source(sid, status="error", error="could not start queued analysis")


def stop_analysis(source_id: str) -> bool:
    """Cancels a real running analysis via its own asyncio Task (tracked per source_id in
    _RUNNING_ANALYSES). NOT instant -- see _run_analysis's own comment on this: a Task cancelled
    while mid-await on a real LLM call only actually raises CancelledError back into it once the
    CURRENT chunk's call returns (Python can't force-kill a running thread-pool call), so this
    takes effect after the in-flight chunk finishes, not mid-request. Whatever techniques were
    already extracted from chunks that DID complete are kept, not thrown away. Returns True if a
    real running task was found and a cancel request was actually sent to it, False if nothing is
    running for this source (already finished, already stopped, or never started)."""
    task = _RUNNING_ANALYSES.get(source_id)
    if task is not None and not task.done():
        task.cancel()
        logger.debug("library: stop requested source=%s", source_id)
        return True
    # Not running -- but it may be QUEUED (waiting for a slot, no task yet). Dequeue it back to a
    # ready state so Stop works on a queued card too, not just a running one.
    source = get_source(source_id)
    if source is not None and source.get("status") == "queued":
        _update_source(source_id, status="normalized", error=None, queued_provider_id=None, queued_model=None, queued_at=None)
        logger.debug("library: dequeued source=%s before it started", source_id)
        return True
    logger.debug("library: stop_analysis found nothing running/queued for source=%s", source_id)
    return False


def count_running_analyses() -> int:
    return sum(1 for t in _RUNNING_ANALYSES.values() if not t.done())
