#!/usr/bin/env python3
"""One-time (re-runnable) harvester for cirt.net's public Default Password Database
(https://cirt.net/passwords/) -- the same source github.com/Viralmaniar/Passhunt reads live via a
plain urllib request. cirt.net now sits behind Cloudflare Bot Management, which rejects a bare HTTP
client outright (confirmed: a plain curl/httpx GET to cirt.net/passwords/?vendor=... returns HTTP
403 "Attention Required! | Cloudflare") -- a real browser genuinely passes it (confirmed live, no
CAPTCHA/challenge screen shown), so this uses the exact same Playwright + stealth-init-script
combination agent/tools/browser_manager.py already runs for every browser_* tool, not a new
technique of its own.

Writes the harvested {vendor: [{product, version, method, user, password, level, note, link}, ...]}
mapping to agent/tools/data/cirt_default_passwords.json -- bundled, source-controlled reference data
(fully public security-research content -- cirt.net's own stated purpose for publishing it at all),
not runtime state. agent/tools/native.py's default_creds_check reads this file's vendor keys instead
of a small hand-typed table.

Respects cirt.net's own robots.txt (Crawl-delay: 10) -- one page navigation every 10+ seconds; ~531
vendors is therefore a genuinely long run (~90 minutes end to end), by design, not a bug to "fix" by
shortening the delay. Saves incrementally after every vendor so an interrupted run loses nothing
already harvested -- re-running the script (or --start-at) picks up where it left off.

Usage (from the project venv, matching run.sh's own WSL2/Linux Playwright install):
    python3 scripts/harvest_cirt_default_passwords.py [--limit N] [--start-at "Vendor Name"]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tools.browser_stealth import STEALTH_INIT_SCRIPT  # noqa: E402

_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "agent" / "tools" / "data" / "cirt_default_passwords.json"
_BASE_URL = "https://cirt.net/passwords/"
_CRAWL_DELAY_SECONDS = 10.0

# cirt.net's own per-vendor table row labels -> this dataset's field names.
_FIELD_KEYS = {
    "Product": "product", "Version": "version", "Method": "method",
    "User": "user", "Pass": "password", "Level": "level", "Note": "note", "Link": "link",
}


async def _fetch_vendor_list(page) -> list[str]:
    await page.goto(_BASE_URL, wait_until="networkidle")
    hrefs = await page.eval_on_selector_all(
        "a[href*='?vendor=']",
        "els => els.map(e => e.getAttribute('href'))",
    )
    seen: set[str] = set()
    vendors: list[str] = []
    for href in hrefs:
        if not href or "vendor=" not in href:
            continue
        name = urllib.parse.unquote_plus(href.split("vendor=", 1)[1])
        if name and name not in seen:
            seen.add(name)
            vendors.append(name)
    return vendors


async def _wait_for_stable_row_count(page, poll_ms: int = 400, stable_polls: int = 3, max_wait_ms: int = 8000) -> None:
    """A multi-entry vendor's page is genuinely ONE single <table> -- confirmed live via
    javascript_tool on Cisco (document.querySelectorAll('table').length === 1, one shared <tbody>)
    -- with every entry's own 8 rows (Product/Version/Method/User/Pass/Level/Note/Link) appended
    back-to-back into that SAME table, and the later entries' rows finish mounting client-side AFTER
    Playwright's networkidle already fires. Polls the live row count instead of trusting a fixed
    sleep (a single-entry vendor legitimately has just 8 rows and shouldn't wait the full
    max_wait_ms for nothing) -- done once the count hasn't changed for `stable_polls` consecutive
    checks in a row.
    """
    last_count = -1
    stable_streak = 0
    elapsed_ms = 0
    while elapsed_ms < max_wait_ms:
        count = await page.eval_on_selector_all("table tr", "els => els.length")
        if count == last_count:
            stable_streak += 1
            if stable_streak >= stable_polls:
                return
        else:
            stable_streak = 0
            last_count = count
        await page.wait_for_timeout(poll_ms)
        elapsed_ms += poll_ms


async def _fetch_vendor_entries(page, vendor: str) -> list[dict]:
    """Real, confirmed incident this fixes: an earlier version of this function grouped rows by
    <table> (one dict per table), which silently collapsed every multi-entry vendor down to just
    its LAST entry -- there is only ONE <table> per vendor page, not one per entry, so that grouping
    built a single dict and kept overwriting the same keys as it walked every entry's rows in turn.
    The real, load-bearing boundary between entries is the recurring "Product" row itself (every
    entry always starts with one) -- grouped on that instead.
    """
    url = _BASE_URL + "?vendor=" + urllib.parse.quote(vendor)
    await page.goto(url, wait_until="networkidle")
    await _wait_for_stable_row_count(page)
    rows = await page.query_selector_all("table tr")
    entries: list[dict] = []
    record: dict = {}
    for row in rows:
        cells = await row.query_selector_all("th, td")
        if len(cells) < 2:
            continue
        label = (await cells[0].inner_text()).strip()
        value = (await cells[1].inner_text()).strip()
        key = _FIELD_KEYS.get(label)
        if key is None:
            continue
        if key == "product" and record:
            if record.get("user") or record.get("password"):
                entries.append(record)
            record = {}
        record[key] = value
    if record.get("user") or record.get("password"):
        entries.append(record)
    return entries


def _load_existing() -> dict[str, list[dict]]:
    if not _OUTPUT_PATH.exists():
        return {}
    try:
        return json.loads(_OUTPUT_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(database: dict[str, list[dict]]) -> None:
    _OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _OUTPUT_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(database, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    tmp.replace(_OUTPUT_PATH)


async def harvest(limit: int | None, start_at: str | None) -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        await context.add_init_script(STEALTH_INIT_SCRIPT)
        page = await context.new_page()

        print("[*] Fetching vendor list...", flush=True)
        vendors = await _fetch_vendor_list(page)
        print(f"[*] Found {len(vendors)} vendors", flush=True)

        if start_at:
            if start_at in vendors:
                vendors = vendors[vendors.index(start_at):]
            else:
                print(f"[!] --start-at {start_at!r} not found in vendor list -- harvesting all", flush=True)
        if limit:
            vendors = vendors[:limit]

        database = _load_existing()

        for i, vendor in enumerate(vendors, 1):
            try:
                entries = await _fetch_vendor_entries(page, vendor)
            except Exception as exc:
                print(f"[!] {i}/{len(vendors)} {vendor}: FAILED ({exc})", flush=True)
                entries = []
            if entries:
                database[vendor] = entries
                print(f"[+] {i}/{len(vendors)} {vendor}: {len(entries)} entrie(s)", flush=True)
            else:
                print(f"[ ] {i}/{len(vendors)} {vendor}: no entries", flush=True)

            _save(database)  # incremental -- a crash/interrupt mid-run loses nothing harvested so far

            if i < len(vendors):
                await asyncio.sleep(_CRAWL_DELAY_SECONDS)

        await browser.close()

    total_entries = sum(len(v) for v in database.values())
    print(f"[*] Done: {len(database)} vendors, {total_entries} entries -> {_OUTPUT_PATH}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Only harvest the first N vendors (testing)")
    parser.add_argument("--start-at", type=str, default=None, help="Resume from this vendor name (skip everything before it in the listing order)")
    args = parser.parse_args()
    asyncio.run(harvest(args.limit, args.start_at))


if __name__ == "__main__":
    main()
