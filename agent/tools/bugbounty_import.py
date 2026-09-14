"""Backs the New Project dialog's own two-button "program URL" wizard bar (templates/partials/
new_project_form.html) -- not a registered agent ToolSpec, just a plain helper module main.py's
wizard routes call directly, same relationship agent/chat.py and agent/tools/chat_settings_store.py
already have to the rest of this package.

Two independent operations, one shared page-fetch helper:
- analyze_bugbounty_program(url): the operator pasted a bug-bounty PROGRAM page (HackerOne/
  Bugcrowd/YesWeHack) -- read it and pre-fill the form's scope/rules fields from what it actually
  says.
- prepare_target_only(url): the operator pasted a concrete web app/URL and wants THAT pentested
  directly -- no program page to read, just turn the link itself into the Target(s) field.

Confirmed live (real browser session against bugcrowd.com/engagements/openai,
hackerone.com/crypto?type=team, yeswehack.com/programs/...) before writing this: all three
platforms are client-rendered SPAs -- a plain HTTP GET (the existing web_fetch native tool) returns
an near-empty shell with no scope table at all; HackerOne's own content arrives entirely via
POST /graphql calls fired after page load. Real Chromium rendering (agent/tools/browser_manager.py,
the same engine backing the browser_* agent tools) is the only thing that actually sees this
content, not a shortcut -- reusing it here rather than reverse-engineering each platform's own
internal API (undocumented, and not meant for third-party scraping).

Also confirmed live, a second time, after an operator report that a real HackerOne program
extracted no scope at all: a HackerOne program's default landing tab ("Program guidelines") never
shows the actual in-scope/out-of-scope asset table -- that lives on a genuinely separate,
directly-navigable route, {program_url}/policy_scopes (confirmed by really clicking that program's
own "Scope and Rewards" sidebar item and watching the URL bar change to exactly that). See
_hackerone_scope_url/_fetch_program_page_text below -- both pages are read and concatenated before
extraction, not just the landing tab.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import httpx

from agent.core import _parse_json_response
from agent.llm_client import get_fallback_chain, get_fallback_chain_enabled, get_next_chain_step, get_provider
from agent.prompts import BUGBOUNTY_PROGRAM_EXTRACTION_PROMPT, DISCLOSED_REPORT_MATCH_PROMPT, DISCLOSED_REPORTS_SUMMARY_PROMPT, RE_PROGRAM_EXTRACTION_PROMPT
from agent.tools.browser_manager import get_browser_manager
from agent.tools.builders.validators import validate_scope_entry
from agent.utils.logger import get_logger
from sessions.store import load_session, reload_merge_save

logger = get_logger("TOOLS")

# How long to let a freshly-"networkidle" SPA keep hydrating before reading its text -- Playwright's
# own networkidle only means "no in-flight network request for 500ms", which fires before a chatty
# React app has necessarily finished turning its last GraphQL response into rendered DOM text.
# Confirmed live: hackerone.com's own scope table needed a real few seconds of wall-clock settle
# time after its last network call before get_page_text-equivalent content actually appeared.
_RENDER_SETTLE_SECONDS = float(os.getenv("BUGBOUNTY_IMPORT_RENDER_SETTLE_SECONDS", "3"))
# Same spirit as native.py's WEB_FETCH_MAX_TEXT_CHARS -- caps one long program page (OpenAI's own
# Bugcrowd brief runs to several thousand words once every target group's own rules are counted)
# before it reaches the LLM extraction call. Generous relative to the actual per-call risk (the
# real budget that matters is the model's own context_limit, routinely six figures of tokens) --
# this exists to keep an already-large HTTP/LLM payload sane, not because 20k was ever observed to
# be tight; raised once a real large program (30+ scope rows) got closer to the old cap than
# comfortable.
_MAX_PAGE_TEXT_CHARS = int(os.getenv("BUGBOUNTY_IMPORT_MAX_PAGE_CHARS", "40000"))
# Keeps a host-derived project name from silently exceeding what the New Project form's own
# "name" field is realistically meant to hold -- not a hard app-wide limit, just a sane cap for an
# auto-derived value nobody typed by hand.
_NAME_FROM_HOST_MAX_LEN = 60
# HackerOne's own /policy_scopes route (real, confirmed live against a 44-asset program) is a
# GraphQL-paginated "load more on scroll" list, not a plain static table -- max real wheel-scroll
# rounds before giving up on loading any further rows, and how long to let each round's own GraphQL
# round trip + re-render settle before checking whether anything new actually appeared.
_SCOPE_HARVEST_MAX_ROUNDS = int(os.getenv("BUGBOUNTY_IMPORT_SCOPE_HARVEST_MAX_ROUNDS", "20"))
_SCOPE_HARVEST_SETTLE_SECONDS = float(os.getenv("BUGBOUNTY_IMPORT_SCOPE_HARVEST_SETTLE_SECONDS", "1.2"))
# A single big wheel jump per round wasn't reliable in live testing -- several smaller, real ticks
# (closer to how an actual person scrolls) crossed the lazy-load library's own intersection/scroll
# trigger threshold far more consistently than one large jump did.
_SCOPE_HARVEST_WHEEL_TICKS_PER_ROUND = 5
_SCOPE_HARVEST_SCROLL_DELTA_PER_TICK = 900
_SCOPE_HARVEST_TICK_PAUSE_SECONDS = 0.15
# refresh_program_check below is called once per agent phase transition (recon/analyze/exploit) --
# this TTL gate is what keeps that cheap: a program's own Hacktivity feed doesn't change fast
# enough to justify a real browser fetch on every single phase transition or finding, but a
# multi-hour session should still notice new disclosures well before it ends. 900s (15 min) is a
# starting point, not a measured constant -- override if a real long-running session needs fresher
# (or cheaper) data.
_HACKTIVITY_REFRESH_SECONDS = int(os.getenv("BUGBOUNTY_IMPORT_HACKTIVITY_REFRESH_SECONDS", "900"))


def _hackerone_scope_url(url: str) -> str | None:
    """Confirmed live (see module docstring): a HackerOne program's own real asset/scope table
    lives on {program_url}/policy_scopes, a genuinely separate route, never shown on the default
    landing tab. Returns None for anything that isn't a specific hackerone.com program page --
    a non-HackerOne host, the bare hackerone.com root (no program handle to build a path from), or
    a URL that's already pointing at that route itself (nothing extra to fetch).
    """
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower()
    if hostname != "hackerone.com" and not hostname.endswith(".hackerone.com"):
        return None
    path = parts.path.rstrip("/")
    if not path or path.endswith("/policy_scopes"):
        return None
    return urlunsplit((parts.scheme, parts.netloc, path + "/policy_scopes", "", ""))


def _hackerone_hacktivity_url(url: str) -> str | None:
    """A HackerOne program's own disclosed-reports feed lives at {program_url}/hacktivity -- the
    same per-program navigation tab a human operator would click (Overview/Policy/Hacktivity),
    scoped to just this one program by virtue of being under its own path. Same URL-derivation
    shape as _hackerone_scope_url above; UNLIKE that route (independently confirmed live against a
    real program during this module's own original development), this one is based on HackerOne's
    documented/standard site navigation rather than re-verified live in this specific session --
    if HackerOne ever restructures it, check_disclosed_reports below degrades to a clear "could not
    read the page" error rather than a silent wrong answer, since it reads the page's own raw
    visible text (same approach _navigate_and_harvest_scrollable_text already uses successfully for
    the sibling /policy_scopes route) rather than depending on specific CSS selectors that could
    quietly stop matching.
    """
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower()
    if hostname != "hackerone.com" and not hostname.endswith(".hackerone.com"):
        return None
    path = parts.path.rstrip("/")
    if not path or path.endswith("/hacktivity"):
        return None
    return urlunsplit((parts.scheme, parts.netloc, path + "/hacktivity", "", ""))


def _bugcrowd_crowdstream_url(url: str) -> str | None:
    """A Bugcrowd program's own disclosed-reports feed lives at {program_url}/crowdstream --
    CONFIRMED LIVE against a real program (bugcrowd.com/engagements/tesla) while building this:
    the program page's own "CrowdStream"/"Hall of Fame" nav links resolve to
    /engagements/<handle>/crowdstream and /engagements/<handle>/hall_of_fames respectively.
    CrowdStream is the one that actually lists disclosed submission titles/rewards/timelines (Hall
    of Fame is just a researcher point leaderboard, no report content at all).

    Bugcrowd's own short program URL form (bugcrowd.com/<handle>, no /engagements/) is a real,
    working client-side redirect -- but ONLY for the bare handle page; confirmed live that
    appending /crowdstream to the short form instead (bugcrowd.com/<handle>/crowdstream) 404s. The
    short form is normalized to the canonical /engagements/<handle> path here before appending,
    rather than trusting it to also redirect a deeper sub-path.
    """
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower()
    if hostname != "bugcrowd.com" and not hostname.endswith(".bugcrowd.com"):
        return None
    segments = [s for s in parts.path.split("/") if s]
    if not segments:
        return None
    if segments[0] == "engagements":
        segments = segments[1:]
    if len(segments) != 1:
        # Not a bare program URL (already /crowdstream, /hall_of_fames, /submissions/new, or some
        # other sub-path) -- nothing sensible to derive a feed URL from.
        return None
    return urlunsplit((parts.scheme, parts.netloc, f"/engagements/{segments[0]}/crowdstream", "", ""))


# YesWeHack has no per-program disclosed-reports equivalent to HackerOne's /hacktivity or
# Bugcrowd's /crowdstream -- CONFIRMED LIVE while building this: a real program page's own
# "Program activity" tab is a JS same-page hash toggle (#program-activity), and the content it
# reveals is a researcher point leaderboard ("HALL OF FAME"), not report titles at all. The only
# place actual disclosed-report content lives is this sitewide feed, un-filterable by program via
# URL (no query-param filter UI found on the live page either) -- returned as a deliberately
# lower-confidence fallback, never silently treated as if it were scoped to just one program.
_YESWEHACK_SITEWIDE_HACKTIVITY_URL = "https://yeswehack.com/hacktivity"


def _yeswehack_sitewide_url(url: str) -> str | None:
    hostname = (urlsplit(url).hostname or "").lower()
    if hostname != "yeswehack.com" and not hostname.endswith(".yeswehack.com"):
        return None
    return _YESWEHACK_SITEWIDE_HACKTIVITY_URL


def _disclosed_reports_feed_url(url: str) -> tuple[str, str] | None:
    """Dispatches a program URL to its platform's own disclosed-reports feed URL. Returns
    (feed_url, platform) where platform is "hackerone", "bugcrowd", or "yeswehack_sitewide" (the
    last one a real, honest caveat baked into the platform label itself -- not scoped to one
    program, see _yeswehack_sitewide_url's own docstring), or None if the host isn't recognized."""
    hacktivity = _hackerone_hacktivity_url(url)
    if hacktivity is not None:
        return hacktivity, "hackerone"
    crowdstream = _bugcrowd_crowdstream_url(url)
    if crowdstream is not None:
        return crowdstream, "bugcrowd"
    yeswehack = _yeswehack_sitewide_url(url)
    if yeswehack is not None:
        return yeswehack, "yeswehack_sitewide"
    return None


async def _fetch_disclosed_reports_text(url: str) -> dict:
    """The raw browser fetch half of check_disclosed_reports below -- dispatch to the right
    platform feed URL, navigate, harvest scrollable text, nothing else. Split out so
    refresh_program_check's own background per-phase cache refresh (every _HACKTIVITY_REFRESH_SECONDS,
    purely to keep _persist_new_finding's automated duplicate check warm) never pays for the
    separate LLM summarization pass check_disclosed_reports adds below -- that pass exists for a
    HUMAN (or the agent's own text-reading judgment) to skim, not for the raw-text cache, which is
    the ONLY thing the background refresh and match_finding_against_disclosed_reports ever need.
    """
    dispatch = _disclosed_reports_feed_url(_normalize_url(url))
    if dispatch is None:
        return {
            "status": "error",
            "error": "Checking disclosed reports is currently only supported for HackerOne, Bugcrowd, or YesWeHack program URLs.",
        }
    feed_url, platform = dispatch

    manager = get_browser_manager()
    session_id = f"disclosed-{uuid.uuid4().hex[:12]}"
    try:
        page = await _navigate_and_harvest_scrollable_text(manager, session_id, feed_url)
        if page["status"] != "ok":
            return page
        text = page["text"][:_MAX_PAGE_TEXT_CHARS]
        if len(page["text"]) > _MAX_PAGE_TEXT_CHARS:
            logger.debug("bugbounty_import: disclosed-reports text truncated to %d chars for url=%r", _MAX_PAGE_TEXT_CHARS, feed_url)
        return {"status": "ok", "text": text, "url": page["url"], "platform": platform}
    finally:
        await manager.close_session(session_id)


async def check_disclosed_reports(url: str) -> dict:
    """Reads a bug-bounty program's own public disclosed-reports feed (HackerOne Hacktivity,
    Bugcrowd CrowdStream, or -- best-effort, sitewide-only -- YesWeHack's own Hacktivity feed) and
    returns an LLM-summarized list of what's already been disclosed, NOT a raw page dump for a
    human (or the calling agent) to skim by hand: DISCLOSED_REPORTS_SUMMARY_PROMPT reads the raw
    scraped text once and extracts real report titles/details into "reports", plus an honest
    "coverage_note" on how complete this view actually is. The raw text is still returned too (as
    "text") for the New Project wizard's own optional "show raw text" fallback -- but the automated,
    no-human-involved per-finding duplicate check (match_finding_against_disclosed_reports) reads
    its OWN separately-cached raw text via _fetch_disclosed_reports_text/refresh_program_check, not
    this function's summary, since comparing one specific finding against the feed needs the raw
    text, not a lossy human-facing summary.

    Real gap this closes: nothing in this project previously checked whether a candidate finding
    was already disclosed -- the operator had to know to go check Hacktivity by hand, separately
    from ASRA entirely. Summarization failure (no LLM provider configured, a bad/empty response)
    degrades gracefully to "reports": [] with the raw text still returned and a coverage_note
    explaining summarization didn't run -- never blocks the raw answer just because the extra
    LLM pass failed, same "advisory only, never a hard gate" posture the rest of this feature has.
    """
    page = await _fetch_disclosed_reports_text(url)
    if page["status"] != "ok":
        return page
    text, platform = page["text"], page["platform"]

    reports: list[dict] = []
    coverage_note = "Could not summarize this feed (no LLM provider configured, or the summarization pass failed) -- see the raw page text below instead."
    if text.strip():
        messages = [
            {"role": "system", "content": DISCLOSED_REPORTS_SUMMARY_PROMPT},
            {"role": "user", "content": text},
        ]
        parsed, error = await _run_extraction_with_reserve_chain(messages)
        if parsed is not None:
            raw_reports = parsed.get("reports")
            if isinstance(raw_reports, list):
                reports = [
                    {"title": str(r.get("title") or "").strip(), "detail": str(r.get("detail") or "").strip()}
                    for r in raw_reports if isinstance(r, dict) and str(r.get("title") or "").strip()
                ]
            coverage_note = str(parsed.get("coverage_note") or "").strip() or coverage_note
        else:
            logger.debug("bugbounty_import: disclosed-reports summarization failed for url=%r (%s)", page["url"], error)
    if platform == "yeswehack_sitewide":
        coverage_note = (
            "YesWeHack has no per-program disclosed-reports page -- this is the platform's SITEWIDE "
            "feed, not filtered to this one program. " + coverage_note
        )

    return {"status": "ok", "reports": reports, "coverage_note": coverage_note, "text": text, "url": page["url"], "platform": platform}


_BLANK_PROGRAM_CHECK = {"last_checked": None, "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None}


def _update_program_check(session_id: str, **fields) -> None:
    """Shared reload-merge-save for refresh_program_check below -- every branch there (HackerOne
    success/failure, non-HackerOne reachability) only ever wants to patch a couple of
    program_check keys without clobbering whatever else session.json holds, and without racing a
    concurrently-running agent phase the way a blind load/mutate/save would (see
    sessions.store.reload_merge_save's own docstring for the real incident this discipline
    generalizes from).
    """
    def _apply(fresh: dict) -> None:
        fresh["program_check"] = {**_BLANK_PROGRAM_CHECK, **(fresh.get("program_check") or {}), **fields}
    reload_merge_save(session_id, _apply)


async def refresh_program_check(session_id: str, program_url: str, force: bool = False) -> None:
    """Best-effort, TTL-gated freshness check for session["program_url"] -- called once per phase
    transition by agent/core.py (a cheap no-op on every call within _HACKTIVITY_REFRESH_SECONDS)
    and once, forced, whenever the operator changes or re-submits the URL via the Overview tab's
    own "Program URL" field (main.py's update_program_url route). Never raises -- a program page
    being briefly unreachable, or genuinely offline, is a normal outcome for an arbitrary
    operator-supplied URL, recorded as program_check["last_error"] rather than surfaced as an
    exception to whichever caller triggered this.

    For a HackerOne/Bugcrowd/YesWeHack program, this also refreshes
    program_check["disclosed_reports_text"] (_fetch_disclosed_reports_text -- the raw fetch only,
    deliberately never check_disclosed_reports's own LLM-summarization pass, which this purely
    internal cache-refresh has no use for) -- agent/core.py's _persist_new_finding reads that cache
    (never fetches it itself, to keep recording a finding non-blocking) to run
    match_finding_against_disclosed_reports below. A program URL on none of those platforms still
    gets a plain reachability read (_navigate_and_read_text) so the Overview tab's own "Last
    checked" isn't silently limited to the platforms this feature covers.
    """
    session = load_session(session_id)
    if session is None:
        return
    if not force:
        cache = session.get("program_check") or {}
        checked_at = cache.get("disclosed_reports_checked_at") or cache.get("last_checked")
        if checked_at:
            try:
                age_seconds = (datetime.now(timezone.utc) - datetime.fromisoformat(checked_at)).total_seconds()
            except ValueError:
                age_seconds = None
            if age_seconds is not None and age_seconds < _HACKTIVITY_REFRESH_SECONDS:
                return

    now = datetime.now(timezone.utc).isoformat()
    if _disclosed_reports_feed_url(program_url) is not None:
        result = await _fetch_disclosed_reports_text(program_url)
        if result.get("status") == "ok":
            _update_program_check(session_id, last_checked=now, last_error=None, disclosed_reports_text=result["text"], disclosed_reports_checked_at=now)
            logger.debug("bugbounty_import: refreshed disclosed-reports cache session_id=%s url=%r (%d chars)", session_id, program_url, len(result["text"]))
        else:
            _update_program_check(session_id, last_checked=now, last_error=result.get("error"))
            logger.debug("bugbounty_import: disclosed-reports refresh failed session_id=%s url=%r (%s)", session_id, program_url, result.get("error"))
        return

    manager = get_browser_manager()
    check_session_id = f"progcheck-{uuid.uuid4().hex[:12]}"
    try:
        page = await _navigate_and_read_text(manager, check_session_id, program_url)
    except Exception as exc:
        page = {"status": "error", "error": str(exc)}
    finally:
        await manager.close_session(check_session_id)
    _update_program_check(session_id, last_checked=now, last_error=None if page.get("status") == "ok" else (page.get("error") or "could not reach the page"))
    logger.debug("bugbounty_import: refreshed reachability session_id=%s url=%r status=%s", session_id, program_url, page.get("status"))


async def match_finding_against_disclosed_reports(disclosed_reports_text: str, finding_title: str, finding_description: str) -> dict:
    """Best-effort duplicate check for agent/core.py's _persist_new_finding -- one small
    structured-extraction LLM call (DISCLOSED_REPORT_MATCH_PROMPT) asking whether a just-recorded
    finding matches any report title already visible in a cached disclosed-reports feed
    (program_check["disclosed_reports_text"], refreshed by refresh_program_check above). Never
    raises and never blocks recording the finding -- {"is_duplicate": False} on any failure (bad/empty LLM
    response, no provider configured, ...) is a normal outcome, the same "badge is pure added
    signal, never a gate" posture the operator asked for; the caller records the finding either way.
    """
    if not disclosed_reports_text.strip() or not finding_title.strip():
        return {"is_duplicate": False}
    messages = [
        {"role": "system", "content": DISCLOSED_REPORT_MATCH_PROMPT},
        {"role": "user", "content": (
            f"Candidate finding title: {finding_title}\nDescription: {finding_description}\n\n"
            f"Program's own disclosed-reports feed text:\n{disclosed_reports_text[:_MAX_PAGE_TEXT_CHARS]}"
        )},
    ]
    parsed, error = await _run_extraction_with_reserve_chain(messages)
    if parsed is None or error:
        logger.debug("bugbounty_import: hacktivity duplicate-match failed for finding_title=%r (%s)", finding_title, error)
        return {"is_duplicate": False}
    if not bool(parsed.get("is_duplicate")):
        return {"is_duplicate": False}
    confidence = str(parsed.get("confidence") or "low").strip().lower()
    if confidence not in ("low", "medium", "high"):
        confidence = "low"
    return {"is_duplicate": True, "matched_title": str(parsed.get("matched_title") or "").strip(), "confidence": confidence}


async def _navigate_and_read_text(manager, session_id: str, url: str) -> dict:
    """One navigate + settle + read.innerText round trip, reused for every page this module reads
    (a program's own landing page, and -- for HackerOne -- its separate scope route below).
    """
    nav = await manager.navigate(session_id, url, wait_until="networkidle")
    if nav["status"] != "ok":
        return {"status": "error", "error": nav.get("error") or nav.get("reason") or "navigation failed"}
    await asyncio.sleep(_RENDER_SETTLE_SECONDS)
    text_result = await manager.evaluate(session_id, "document.body.innerText")
    if text_result["status"] != "ok":
        return {"status": "error", "error": text_result.get("error") or "could not read the page's own text"}
    return {
        "status": "ok",
        "text": str(text_result.get("eval_result") or ""),
        "title": text_result.get("title") or "",
        "url": text_result.get("url") or url,
    }


async def _navigate_and_harvest_scrollable_text(manager, session_id: str, url: str) -> dict:
    """Same navigate+settle+read as _navigate_and_read_text above, but for a page whose real
    content is a scroll-triggered "load more" list rather than everything already present on one
    static read -- confirmed live against a real HackerOne program: the page's own "1-44 of 44"
    label was correct, but a single read (even after the usual settle delay) only ever showed ~19
    of the 44 real assets, because the rest only load in as the operator scrolls further.

    Repeatedly wheel-scrolls (browser_manager.mouse_wheel_scroll -- a genuine, trusted input event;
    see that method's own docstring for why a programmatic scrollTop assignment does NOT work here
    at all) and re-reads document.body.innerText, keeping the latest (content only ever grows here,
    never slides back out) snapshot, until a round produces no new text at all or the round cap is
    hit -- whichever comes first. A page that needs no scrolling (nothing new after the very first
    read) still returns correctly; this never assumes the target actually has a "load more" list.

    "domcontentloaded", not "networkidle" like _navigate_and_read_text's own primary-page fetch --
    real, confirmed live incident: this exact HackerOne scope route timed out its own full
    BROWSER_ACTION_TIMEOUT_SECONDS budget waiting for "networkidle", which never fired at all
    (some background polling/analytics connection on the page apparently never goes fully idle).
    The harvest loop below already has its own repeated settle-and-check discipline (each round
    waits _SCOPE_HARVEST_SETTLE_SECONDS and re-reads), so it doesn't actually depend on the initial
    navigation itself having fully settled first the way a single-read fetch would.
    """
    nav = await manager.navigate(session_id, url, wait_until="domcontentloaded")
    if nav["status"] != "ok":
        return {"status": "error", "error": nav.get("error") or nav.get("reason") or "navigation failed"}
    # domcontentloaded fires well before networkidle would have -- before React has necessarily
    # even mounted, let alone fetched+rendered its first page of scope rows. Double the usual
    # settle budget here specifically so the very first read isn't checked before anything real
    # has actually rendered yet (confirmed live: a bare _RENDER_SETTLE_SECONDS wait here made the
    # harvest loop "stabilize" after a single round on an effectively still-empty page).
    await asyncio.sleep(_RENDER_SETTLE_SECONDS * 2)

    last_text = None
    final_text = ""
    title = ""
    final_url = url
    for round_index in range(_SCOPE_HARVEST_MAX_ROUNDS):
        text_result = await manager.evaluate(session_id, "document.body.innerText")
        if text_result["status"] != "ok":
            break
        title = text_result.get("title") or title
        final_url = text_result.get("url") or final_url
        text = str(text_result.get("eval_result") or "")
        if text == last_text:
            logger.debug("bugbounty_import: scroll-harvest for %r stabilized after %d round(s)", url, round_index)
            break
        final_text = text
        last_text = text
        scroll_failed = False
        for _tick in range(_SCOPE_HARVEST_WHEEL_TICKS_PER_ROUND):
            scroll_result = await manager.mouse_wheel_scroll(session_id, _SCOPE_HARVEST_SCROLL_DELTA_PER_TICK)
            if scroll_result["status"] != "ok":
                logger.debug("bugbounty_import: scroll-harvest wheel scroll failed for %r (%s)", url, scroll_result.get("error"))
                scroll_failed = True
                break
            await asyncio.sleep(_SCOPE_HARVEST_TICK_PAUSE_SECONDS)
        if scroll_failed:
            break
        await asyncio.sleep(_SCOPE_HARVEST_SETTLE_SECONDS)
    else:
        logger.debug("bugbounty_import: scroll-harvest for %r hit its own %d-round cap", url, _SCOPE_HARVEST_MAX_ROUNDS)

    if not final_text:
        return {"status": "error", "error": "could not read the page's own text"}
    return {"status": "ok", "text": final_text, "title": title, "url": final_url}


async def _fetch_program_page_text(url: str) -> dict:
    """Opens a throwaway browser_manager session, reads the fully-rendered page's own visible text
    (document.body.innerText -- the same real content a sighted operator would see, not a markup
    dump), and always tears the session back down again. Session id is scoped to this one call
    (never a real session_id) -- this can run before any project/session exists at all, which is
    exactly the point of the wizard: it prepares the New Project form, it doesn't require one
    already being open.

    For a HackerOne program specifically, also reads its separate /policy_scopes route
    (_hackerone_scope_url) in the SAME browser session/context and appends its text -- the landing
    page alone never has a real scope table on it at all (see module docstring), so skipping this
    would leave the extraction with rules/policy but no actual in-scope hosts, every time.
    """
    manager = get_browser_manager()
    session_id = f"wizard-{uuid.uuid4().hex[:12]}"
    try:
        primary = await _navigate_and_read_text(manager, session_id, url)
        if primary["status"] != "ok":
            return primary

        primary_text = primary["text"]
        scope_text = ""
        scope_url = _hackerone_scope_url(primary["url"])
        if scope_url:
            logger.debug("bugbounty_import: hackerone.com program detected -- also reading %r", scope_url)
            scope_page = await _navigate_and_harvest_scrollable_text(manager, session_id, scope_url)
            if scope_page["status"] == "ok" and scope_page["text"].strip():
                scope_text = scope_page["text"]
            else:
                logger.debug(
                    "bugbounty_import: hackerone scope page fetch skipped url=%r (%s)",
                    scope_url, scope_page.get("error"),
                )

        # Fair-share truncation between the two pages, neither one able to fully starve the other.
        # This replaced an earlier fix that gave the scope section its own FULL budget first and
        # let the primary/guidelines text take only whatever was left -- confirmed live against a
        # real program (kiwicom, hackerone.com/kiwicom) whose scroll-harvested scope table alone
        # exceeded the entire _MAX_PAGE_TEXT_CHARS budget on its own: primary_budget worked out to
        # exactly 0, silently deleting the ENTIRE landing page before it ever reached the LLM --
        # including its real "Rules of engagement" and "Out of scope vulnerabilities & exclusions"
        # sections, both plainly present on the real page. That earlier fix's own comment describes
        # the OPPOSITE incident it was written for (a long guidelines page crowding out the scope
        # section) -- fixing one direction while leaving the other just as exposed is the exact
        # "fixed the bug, introduced the same bug in reverse" pattern this project has hit before.
        # Fair-share policy instead: each section gets up to half the budget; a section that's
        # naturally shorter than its own half hands the unused leftover to the other, so neither a
        # short guidelines page nor a short scope table wastes room the other genuinely needs.
        if scope_text:
            half_budget = _MAX_PAGE_TEXT_CHARS // 2
            if len(primary_text) <= half_budget:
                primary_budget = len(primary_text)
                scope_budget = _MAX_PAGE_TEXT_CHARS - primary_budget
            elif len(scope_text) <= half_budget:
                scope_budget = len(scope_text)
                primary_budget = _MAX_PAGE_TEXT_CHARS - scope_budget
            else:
                primary_budget = half_budget
                scope_budget = _MAX_PAGE_TEXT_CHARS - half_budget
            primary_text = primary_text[:primary_budget]
            scope_text = scope_text[:scope_budget]
            combined_text = primary_text + "\n\n--- Scope & Rewards page ---\n\n" + scope_text
        else:
            combined_text = primary_text[:_MAX_PAGE_TEXT_CHARS]

        if len(primary["text"]) + len(scope_text) > _MAX_PAGE_TEXT_CHARS:
            logger.debug("bugbounty_import: page text truncated to %d chars for url=%r", _MAX_PAGE_TEXT_CHARS, url)
        return {"status": "ok", "text": combined_text, "title": primary["title"], "url": primary["url"]}
    finally:
        await manager.close_session(session_id)


def _normalize_url(raw: str) -> str:
    return raw if "://" in raw else f"https://{raw}"


def _clean_scope_field(raw: object, *, allow_free_text: bool = False) -> str:
    """Runs the LLM's own comma-separated scope output back through this app's real scope-entry
    validator (the exact same one main.py's /api/scan applies on submit) -- an entry the model
    hallucinated in a shape that isn't actually a host/URL/wildcard is dropped rather than shown to
    the operator as if it were usable. allow_free_text (out_of_scope only, mirroring that field's
    own server-side fallback) keeps a plain-language exclusion phrase instead of discarding it --
    Target(s) has no such fallback, so an invalid target entry is simply dropped, never kept.

    Deduped (case-insensitive, first-occurrence order kept) after validation -- real, confirmed
    behavior: a bug-bounty program's own scope table commonly lists the same host again under a
    second target group/reward tier, and the model echoes it just as many times, which used to
    hand the operator a Target(s) field with the same entry typed out several times over.
    """
    if not raw:
        return ""
    entries = [entry.strip() for entry in str(raw).split(",") if entry.strip()]
    cleaned: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        try:
            value = validate_scope_entry(entry)
        except ValueError:
            if not allow_free_text:
                continue
            value = entry
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(value)
    return ", ".join(cleaned)


def _extraction_failure_message(exc: Exception) -> str:
    """The operator-facing text for both analyze_bugbounty_program/analyze_re_program's own
    LLM-call except blocks below. agent/llm_client.py's own _call_with_backoff already retries a
    429/5xx up to 5 times (~60s of real backoff) before ever re-raising -- so an exception reaching
    here means the provider kept failing through every one of those retries, not that ASRA never
    tried. A bare str(exc) on a retryable openai.APIStatusError renders as the provider's raw JSON
    error body verbatim (confirmed live: "Error code: 500 - {'type': 'error', 'error': {'type':
    'error', 'message': 'Internal server error'}}") with nothing telling the operator a retry
    sequence already happened -- looks exactly like ASRA gave up instantly on the first try, not
    after a real minute of backoff. Every other exception shape (a genuine config/auth error, a
    malformed-request 4xx, a connection drop) still gets its own real message -- only a confirmed
    retryable status code gets this friendlier substitution.
    """
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int) and (status_code == 429 or status_code >= 500):
        return (
            "The AI provider kept failing (repeated 429/5xx errors) even after several automatic "
            "retries — try again in a moment, or switch providers under Settings → LLM Provider."
        )
    return f"The extraction step failed: {exc}"


async def _run_extraction_with_reserve_chain(messages: list[dict]) -> tuple[dict | None, str | None]:
    """Runs an extraction prompt (analyze_bugbounty_program/analyze_re_program's own messages)
    against the main agent's configured LLM, walking the operator's own reserve chain (Settings ->
    Reserve providers -- the exact same get_fallback_chain/get_next_chain_step agent/core.py's
    _llm_complete already uses mid-session) when the first attempt either raises OR comes back with
    every single field blank.

    Real, confirmed incident this fixes: a real HackerOne program page (redox_bbp) was fetched
    correctly TWICE, byte-for-byte the same real scope table both times, sent to the exact same
    model both times -- one run produced a complete, correct extraction (name/target/out_of_scope/
    everything), the other silently returned an all-blank JSON shell with no error at all. That is
    not "this page has no scope," it is the model giving up partway through a long structured-
    extraction prompt -- previously indistinguishable from a genuinely scope-less page, and with no
    retry of any kind, not even on the same provider. All-blank (not just target blank) is the
    trigger, not just an empty target -- analyze_re_program's own target is legitimately allowed to
    be empty for a real page (a program that names no RE-relevant asset), so target-blank alone
    would misfire a reserve-chain switch on every genuinely-targetless RE page.

    Returns (parsed_dict, None) once a real (non-blank) result comes back, or (None, error_message)
    once every step has been tried (or just the first, if no reserve chain is configured/enabled).
    """
    tried_steps: set[tuple[str, str]] = set()
    last_error: str | None = None
    try:
        llm = get_provider(None, None)
    except Exception as exc:
        return None, f"No LLM provider available: {exc}"

    while True:
        tried_steps.add((llm.provider_id, llm.model))
        try:
            response = await asyncio.to_thread(llm.complete, messages, None)
            parsed = _parse_json_response(response.content)
            if isinstance(parsed, dict) and any(str(value).strip() for value in parsed.values()):
                return parsed, None
            last_error = None if isinstance(parsed, dict) else (
                "Read the page, but couldn't extract structured fields from it — try pasting the "
                "program's own rules into \"Custom instructions\" manually instead."
            )
            logger.debug(
                "bugbounty_import: extraction returned %s for provider=%s model=%s",
                "an all-blank result" if last_error is None else "unusable JSON", llm.provider_id, llm.model,
            )
        except Exception as exc:
            logger.debug("bugbounty_import: extraction call failed for provider=%s model=%s (%s)", llm.provider_id, llm.model, exc)
            last_error = _extraction_failure_message(exc)

        if not get_fallback_chain_enabled():
            break
        fallback = get_next_chain_step(get_fallback_chain(), tried_steps)
        if fallback is None:
            break
        logger.debug("bugbounty_import: retrying extraction via reserve provider=%s model=%s", fallback.provider_id, fallback.model)
        llm = fallback  # use the already-resolved reserve provider directly -- re-resolving it via
        # get_provider(provider_id, model) here (an earlier draft of this function did) is not just
        # redundant, it's a real, confirmed bug: it silently discards the very provider instance
        # get_next_chain_step just picked and asks get_provider for provider_id/model all over
        # again, which for a mocked/stubbed get_provider in a test (or any caller-supplied override)
        # never matches the reserve step at all -- tried_steps then never gains the reserve step's
        # real identity, get_next_chain_step keeps returning "not yet tried" for it forever, and the
        # loop never terminates. Caught by a genuine infinite-loop hang in this function's own test.

    return None, last_error or "Read the page, but couldn't extract structured fields from it."


async def analyze_bugbounty_program(url: str) -> dict:
    """Button 1 -- reads a bug-bounty PROGRAM page and pre-fills the New Project form's scope/rules
    fields from what it actually says (BUGBOUNTY_PROGRAM_EXTRACTION_PROMPT). Returns
    {"status": "ok", name, target, out_of_scope, qualifying_vulnerabilities,
    non_qualifying_vulnerabilities, custom_instructions, custom_user_agent, user_agent_snippet,
    custom_headers} or {"status": "error", "error": "..."} -- never raises, every failure mode (bad
    URL, page didn't render, no LLM provider configured, the model returned unusable JSON) is a
    normal, expected outcome for an operator pasting an arbitrary link, not a server error.

    custom_user_agent vs. user_agent_snippet: two different fields for two different program
    requirements, not a duplicate. custom_user_agent is a full, exact, literal UA string a program
    demands verbatim (rare). user_agent_snippet is the far more common case -- a short identifying
    token a program asks to be appended to the researcher's OWN real browser UA (confirmed live: a
    YesWeHack program's own instruction, "add bug-bounty-HunterName to your User-Agent, replace
    HunterName with your nickname") -- main.py routes this into the New Project form's existing
    "Program-required snippet" input (the one "Merge into my browser's UA" already reads), never
    into custom_user_agent, since overwriting the operator's real browser UA with a bare literal
    string like "bug-bounty-HunterName" is itself a worse anti-bot fingerprint than a real UA with
    one extra token, the exact problem that Merge button already exists to avoid.
    """
    raw = (url or "").strip()
    if not raw:
        return {"status": "error", "error": "Enter a program page URL first."}
    target_url = _normalize_url(raw)
    if urlsplit(target_url).scheme.lower() not in ("http", "https"):
        return {"status": "error", "error": f"{raw!r} doesn't look like a valid http(s) URL."}

    logger.debug("bugbounty_import: analyzing program page url=%r", target_url)
    page = await _fetch_program_page_text(target_url)
    if page["status"] != "ok":
        logger.debug("bugbounty_import: fetch failed for url=%r (%s)", target_url, page.get("error"))
        return {"status": "error", "error": f"Couldn't open that page: {page['error']}"}
    if not page["text"].strip():
        return {
            "status": "error",
            "error": "The page loaded but had no readable text — it may require a login, or block automated browsing.",
        }

    messages = [
        {"role": "system", "content": BUGBOUNTY_PROGRAM_EXTRACTION_PROMPT},
        {"role": "user", "content": f"Program page URL: {page['url']}\nPage title: {page['title']}\n\n{page['text']}"},
    ]
    parsed, error = await _run_extraction_with_reserve_chain(messages)
    if parsed is None:
        logger.debug("bugbounty_import: extraction failed for url=%r (%s)", target_url, error)
        return {"status": "error", "error": error}

    fields = {
        "name": str(parsed.get("name") or "").strip()[:_NAME_FROM_HOST_MAX_LEN],
        "target": _clean_scope_field(parsed.get("target")),
        "out_of_scope": _clean_scope_field(parsed.get("out_of_scope"), allow_free_text=True),
        "qualifying_vulnerabilities": str(parsed.get("qualifying_vulnerabilities") or "").strip(),
        "non_qualifying_vulnerabilities": str(parsed.get("non_qualifying_vulnerabilities") or "").strip(),
        "custom_instructions": str(parsed.get("custom_instructions") or "").strip(),
        "custom_user_agent": str(parsed.get("custom_user_agent") or "").strip(),
        "user_agent_snippet": str(parsed.get("user_agent_snippet") or "").strip(),
        "custom_headers": str(parsed.get("custom_headers") or "").strip(),
    }
    _reroute_misplaced_ua(fields)
    if not fields["target"]:
        logger.debug("bugbounty_import: no in-scope targets extracted for url=%r", target_url)
        return {
            "status": "error",
            "error": "Read the page, but couldn't find a concrete in-scope target/host in its scope table — "
                     "either this isn't actually a bug-bounty program page (use \"Use this link as the "
                     "target\" instead if you meant to pentest this exact site), or the scope table needs "
                     "entering manually.",
            **fields,
        }
    logger.debug("bugbounty_import: extracted fields for url=%r name=%r target=%r", target_url, fields["name"], fields["target"])
    return {"status": "ok", **fields}


_RE_PROGRAM_FIELDS = ("name", "target", "goal", "qualifying_vulnerabilities", "non_qualifying_vulnerabilities", "custom_instructions")


async def analyze_re_program(url: str) -> dict:
    """The Reverse Engineering New Project panel's own "Analyze program/resource link" button --
    reads a real bug-bounty/vulnerability-disclosure PROGRAM page (the exact same kind of page
    analyze_bugbounty_program below reads for Agent mode -- HackerOne/Bugcrowd/YesWeHack/a project's
    own security policy) and pulls out just the reverse-engineering-relevant scope entries from its
    scope table (a source repo, a smart-contract address, a downloadable binary/package), plus
    RE-scoped qualifying/non-qualifying vulnerability classes and a goal, from what it actually says
    (RE_PROGRAM_EXTRACTION_PROMPT). Mirrors analyze_bugbounty_program's own shape (same shared
    _fetch_program_page_text/_parse_json_response plumbing, same "never invent a field, error is a
    normal outcome" discipline), but deliberately does NOT reuse that function's own target-cleaning
    (_clean_scope_field runs validate_scope_entry, a host/URL shape check that doesn't fit an RE
    target at all -- a local file path or a git repo URL, never a bare host/URL scope entry) or its
    own required-target error (a program page can legitimately name zero, one, or several RE-relevant
    assets -- an empty or multi-entry target here is a normal, non-error outcome either way, shown to
    the operator as removable chips just like Agent mode's own Target(s) field, main.py's start_re
    route and agent/tools/builders/re_target.py's own comma-separated multi-target support).

    Returns {"status": "ok", name, target, goal, qualifying_vulnerabilities,
    non_qualifying_vulnerabilities, custom_instructions} or {"status": "error", "error": "...",
    **whatever was genuinely extracted} -- never raises.
    """
    raw = (url or "").strip()
    if not raw:
        return {"status": "error", "error": "Enter a program/resource page URL first."}
    target_url = _normalize_url(raw)
    if urlsplit(target_url).scheme.lower() not in ("http", "https"):
        return {"status": "error", "error": f"{raw!r} doesn't look like a valid http(s) URL."}

    logger.debug("bugbounty_import: analyzing RE program/resource page url=%r", target_url)
    page = await _fetch_program_page_text(target_url)
    if page["status"] != "ok":
        logger.debug("bugbounty_import: fetch failed for url=%r (%s)", target_url, page.get("error"))
        return {"status": "error", "error": f"Couldn't open that page: {page['error']}"}
    if not page["text"].strip():
        return {
            "status": "error",
            "error": "The page loaded but had no readable text — it may require a login, or block automated browsing.",
        }

    messages = [
        {"role": "system", "content": RE_PROGRAM_EXTRACTION_PROMPT},
        {"role": "user", "content": f"Page URL: {page['url']}\nPage title: {page['title']}\n\n{page['text']}"},
    ]
    parsed, error = await _run_extraction_with_reserve_chain(messages)
    if parsed is None:
        logger.debug("bugbounty_import: RE extraction failed for url=%r (%s)", target_url, error)
        return {"status": "error", "error": error}

    fields = {field: str(parsed.get(field) or "").strip() for field in _RE_PROGRAM_FIELDS}
    fields["name"] = fields["name"][:_NAME_FROM_HOST_MAX_LEN]
    logger.debug("bugbounty_import: extracted RE fields for url=%r name=%r target=%r", target_url, fields["name"], fields["target"])
    return {"status": "ok", **fields}


_UA_ENGINE_MARKERS = ("mozilla", "applewebkit", "gecko", "chrome/", "safari/", "firefox/", "opera/", "opr/", "edg/", "version/")


def _reroute_misplaced_ua(fields: dict) -> None:
    """Server-side safety net on top of BUGBOUNTY_PROGRAM_EXTRACTION_PROMPT's own mechanical
    custom_user_agent/user_agent_snippet rule -- a free-tier model can still get this wrong
    (confirmed live: it occasionally puts a bare literal append-token, e.g. "MCN-Prime-aux-bogues",
    straight into custom_user_agent instead of user_agent_snippet). A real User-Agent string always
    names at least one browser-engine token (Mozilla/AppleWebKit/Gecko/Chrome/Safari/...); a bare
    identifying token a program wants appended never does. Mutates fields in place -- if
    custom_user_agent doesn't look like a real UA and user_agent_snippet is still empty, move it
    there instead of silently letting it overwrite the operator's own real browser UA outright with
    an anomalous-looking string that would flag every request as non-browser traffic.
    """
    value = fields.get("custom_user_agent", "")
    if not value or fields.get("user_agent_snippet"):
        return
    if any(marker in value.lower() for marker in _UA_ENGINE_MARKERS):
        return
    logger.debug("bugbounty_import: custom_user_agent %r doesn't look like a real browser UA -- rerouted to user_agent_snippet", value)
    fields["user_agent_snippet"] = value
    fields["custom_user_agent"] = ""


_SECURITY_TXT_TIMEOUT_SECONDS = float(os.getenv("BUGBOUNTY_IMPORT_SECURITY_TXT_TIMEOUT_SECONDS", "5"))
# RFC 9116's own published-policy text is typically short (Contact/Policy/Preferred-Languages/
# Canonical lines) -- this caps a pathological host that serves something huge at that path.
_SECURITY_TXT_MAX_CHARS = 2000


async def _fetch_page_title(target_value: str) -> str:
    """Best-effort real page title for a nicer project name than the bare hostname.

    Real, confirmed bug this fixes: an earlier version reused the plain-HTTP web_fetch native tool
    (agent/tools/native.py, a bare httpx GET + regex on the raw response HTML) for this -- exactly
    the same class of mistake this module's own docstring already warns about for program pages: a
    modern JS-rendered site's initial HTML response commonly carries a generic/build-tool <title>
    (or none at all) that only becomes the real page title once client-side JS runs and sets
    document.title, which a plain HTTP GET never sees. Uses the same real Chromium render
    (_navigate_and_read_text, an ephemeral browser_manager session) button 1's own program-page
    analysis already relies on for exactly this reason, instead of a second, weaker fetch path.
    Any failure (timeout, 404, DNS, Chromium unavailable) is a normal, expected outcome for an
    arbitrary operator-supplied URL, never worth surfacing as an error -- the hostname-derived name
    is already a perfectly fine fallback.
    """
    fetch_url = target_value if target_value.startswith(("http://", "https://")) else f"https://{target_value}"
    manager = get_browser_manager()
    session_id = f"wizard-{uuid.uuid4().hex[:12]}"
    try:
        page = await _navigate_and_read_text(manager, session_id, fetch_url)
    except Exception as exc:
        logger.debug("bugbounty_import: page-title fetch failed for %r (%s)", fetch_url, exc)
        return ""
    finally:
        await manager.close_session(session_id)
    if page.get("status") == "ok" and page.get("title"):
        return str(page["title"]).strip()
    return ""


def _fetch_security_txt(hostname: str, preferred_scheme: str) -> str:
    """Best-effort RFC 9116 published-policy check -- real, confirmed value this adds: plenty of
    real companies with no third-party bug-bounty platform at all still publish a security.txt with
    real contact/policy/scope information at this exact, standardized well-known path. A 404/
    timeout/connection failure here is the normal, expected outcome for most sites (most don't
    publish one) -- never an error worth surfacing, just an empty result.
    """
    for scheme in dict.fromkeys((preferred_scheme, "https", "http")):  # try preferred once, no dup
        fetch_url = f"{scheme}://{hostname}/.well-known/security.txt"
        try:
            with httpx.Client(timeout=_SECURITY_TXT_TIMEOUT_SECONDS, follow_redirects=True) as client:
                response = client.get(fetch_url)
        except httpx.HTTPError as exc:
            logger.debug("bugbounty_import: security.txt fetch failed for %r (%s)", fetch_url, exc)
            continue
        if response.status_code == 200 and response.text.strip():
            logger.debug("bugbounty_import: found a published security.txt at %r", fetch_url)
            return response.text.strip()[:_SECURITY_TXT_MAX_CHARS]
    return ""


async def prepare_target_only(url: str) -> dict:
    """Button 2 -- the pasted link IS the pentest target, not a program page to read for scope.
    Real, confirmed operator complaint this addresses: an earlier version only ever rewrote the
    pasted text into Target(s)/Name via pure string parsing -- "something I could've typed myself".
    No LLM call (the operator already knows exactly what they want tested), but now does two
    best-effort real checks against the target itself: its own real, JS-rendered page title (a
    better project name than the bare hostname -- see _fetch_page_title's own docstring for why
    this needs a real browser render, not a plain HTTP GET) and RFC 9116's standardized
    /.well-known/security.txt path (real published contact/policy info many companies publish even
    without a formal bug-bounty platform) -- surfaced as custom_instructions so the operator sees it
    before the scan starts, not buried. Either check failing (most sites have no security.txt at
    all) is a normal outcome, never an error; the operator always still gets Name + Target at
    minimum, same as before this existed.

    Returns {"status": "ok", "name": ..., "target": ..., "custom_instructions": ...} or
    {"status": "error", "error": "..."}.
    """
    raw = (url or "").strip()
    if not raw:
        return {"status": "error", "error": "Enter a target URL first."}

    # "//" (not the raw string, and never a forced https:// like analyze_bugbounty_program above)
    # -- lets urlsplit resolve a real hostname regardless of whether the operator typed a scheme,
    # without silently rewriting a bare-host paste ("example.com") into a URL they never typed;
    # validate_scope_entry right below still validates the operator's ORIGINAL raw text, exactly as
    # they typed it, the same shape the Target(s) field itself already accepts unchanged.
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    hostname = parsed.hostname
    if not hostname:
        return {"status": "error", "error": f"{raw!r} doesn't look like a valid URL/host."}
    try:
        target_value = validate_scope_entry(raw)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    name = hostname[4:] if hostname.startswith("www.") else hostname
    name = name[:_NAME_FROM_HOST_MAX_LEN]
    page_title = await _fetch_page_title(target_value)
    if page_title:
        name = page_title[:_NAME_FROM_HOST_MAX_LEN]

    custom_instructions = ""
    security_txt = _fetch_security_txt(hostname, parsed.scheme or "https")
    if security_txt:
        custom_instructions = f"Found a published security.txt at this target's own /.well-known/security.txt:\n\n{security_txt}"

    logger.debug(
        "bugbounty_import: prepared target-only fields url=%r name=%r target=%r security_txt_found=%s",
        raw, name, target_value, bool(security_txt),
    )
    return {"status": "ok", "name": name, "target": target_value, "custom_instructions": custom_instructions}
